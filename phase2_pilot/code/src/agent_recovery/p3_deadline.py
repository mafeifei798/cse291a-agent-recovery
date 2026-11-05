"""Process-isolated HTTPS exchange with a parent-owned monotonic deadline.

The worker receives wire bytes and an explicit credential, never a workflow,
SQLite handle, gateway or credential provider. Only the parent may publish a
response. Local termination makes no assertion about upstream cancellation or
billing. Finite recipes exercise the same supervision without opening sockets.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import multiprocessing
import os
import selectors
import signal
import struct
import sys
from time import monotonic, sleep
from uuid import uuid4

from .contracts import ContractError, canonical_json, require
from .p3_transport import (
    HTTPRequest, HTTPResponse, LiveRuntimePermit, P3Binding, P3HTTPError,
    StdlibHTTPSender, fake_http_response,
)

_MAX_FRAME_BYTES = 4 * 1024 * 1024
_MAX_BODY_BYTES = 2 * 1024 * 1024
_RECIPE_KINDS = {
    "response", "dns_hang", "slow_headers", "slow_body", "late_success",
    "worker_crash", "truncated_ipc", "ignore_term", "cleanup_failure",
    "forbidden_network", "forbidden_sqlite", "forbidden_subprocess", "worker_exception",
    "public_workflow",
    "delayed_exit",
    "truncated_header", "empty_ipc",
}
SPAWN_IN_PROGRESS = False


def spawn_allowed():
    """Narrow audit hook signal: true only while starting our own child."""
    return SPAWN_IN_PROGRESS


@dataclass(frozen=True)
class WireRecipe:
    """One finite socket-free worker action; never falls back to real HTTPS."""

    kind: str = "response"
    response: HTTPResponse | None = None
    delay_s: float = 0.0
    follow_attacks: bool = False

    def __post_init__(self):
        require(self.kind in _RECIPE_KINDS, "Unknown bounded HTTP recipe", "P3_FIXTURE_ERROR")
        require(type(self.delay_s) in (int, float) and math.isfinite(self.delay_s)
                and 0 <= self.delay_s <= 300,
                "Invalid bounded HTTP recipe delay", "P3_FIXTURE_ERROR")
        require(self.response is None or isinstance(self.response, HTTPResponse),
                "Recipe response must be a wire fixture", "P3_FIXTURE_ERROR")
        require(type(self.follow_attacks) is bool,
                "Public wire recipe attack policy must be explicit", "P3_FIXTURE_ERROR")
        if self.kind in ("response", "slow_headers", "slow_body", "late_success", "cleanup_failure", "delayed_exit"):
            require(isinstance(self.response, HTTPResponse),
                    "Recipe requires a wire response", "P3_FIXTURE_ERROR")


def _response_packet(response):
    require(isinstance(response, HTTPResponse) and type(response.status) is int
            and isinstance(response.headers, dict) and isinstance(response.body, bytes)
            and len(response.body) <= _MAX_BODY_BYTES,
            "Invalid worker HTTP response", "P3_TRANSPORT_ERROR")
    # Never send arbitrary authorization, proxy or cookie headers over IPC.
    headers = {str(k).lower(): v for k, v in response.headers.items()
               if str(k).lower() in ("x-request-id", "request-id", "x-litellm-call-id", "content-type")
               and isinstance(v, str)}
    return {"kind": "response", "status": response.status, "headers": headers,
            "body_b64": base64.b64encode(response.body).decode("ascii")}


def _emit(connection, packet):
    payload = canonical_json(packet).encode("utf-8")
    require(len(payload) <= _MAX_FRAME_BYTES, "IPC response too large", "P3_TRANSPORT_ERROR")
    # A fixed, bounded frame lets the parent read non-blockingly. recv_bytes()
    # could wait beyond deadline after receiving only part of a large frame.
    value = struct.pack("!I", len(payload)) + payload
    while value:
        written = os.write(connection.fileno(), value)
        value = value[written:]


def _offline_audit(event, args):
    if (event.startswith("socket.") or event.startswith("sqlite3.")
            or event in {"http.client.connect", "subprocess.Popen", "os.system", "os.fork", "os.posix_spawn"}
            or event.startswith("os.spawn")):
        raise RuntimeError("A fixture worker attempted a forbidden external effect")


def _reject_credential_echo(response, authorization):
    """Keep an upstream echo of this exact credential inside the worker.

    Recognizable key patterns are insufficient for opaque provider keys. Check
    raw response bytes and decoded JSON strings before sending anything over
    IPC; this deliberately discards usage too when the response is tainted.
    """
    if authorization is None:
        return
    require(type(authorization) is str and bool(authorization)
            and isinstance(response, HTTPResponse)
            and isinstance(response.headers, dict) and isinstance(response.body, bytes)
            and len(response.body) <= _MAX_BODY_BYTES,
            "Invalid credential-safe worker response", "P3_NETWORK_ERROR")

    def contains(value):
        pending = [value]
        while pending:
            current = pending.pop()
            if isinstance(current, str):
                if authorization in current:
                    return True
                # Header values and JSON message fields can themselves hold
                # JSON-quoted text. Inspect that decoded string as well.
                try:
                    decoded = json.loads(current)
                except (ValueError, UnicodeError):
                    decoded = None
                if isinstance(decoded, (str, dict, list)) and decoded != current:
                    pending.append(decoded)
            elif isinstance(current, dict):
                pending.extend(current.keys())
                pending.extend(current.values())
            elif isinstance(current, (list, tuple)):
                pending.extend(current)
        return False

    tainted = authorization.encode("utf-8") in response.body or contains(response.headers)
    if not tainted:
        try:
            decoded = json.loads(response.body)
        except (ValueError, UnicodeError):
            decoded = None
        tainted = contains(decoded)
    if tainted:
        # The parent only receives this fixed code, never body, headers, usage
        # or exception text. Consumption remains unknown and held in full.
        raise P3HTTPError("P3_NETWORK_ERROR", dispatched=True)


def _worker(connection, payload, recipe):
    """Spawn entrypoint: no parent callables or workflow objects are accepted."""
    try:
        for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                     "NUMEXPR_NUM_THREADS"):
            os.environ[name] = "1"
        os.environ["CUDA_VISIBLE_DEVICES"] = ""
        if hasattr(os, "nice"):
            os.nice(max(0, 19 - os.nice(0)))
        if recipe is not None:
            sys.addaudithook(_offline_audit)
            kind = recipe["kind"]
            if kind in ("ignore_term", "late_success") and hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if kind in ("dns_hang", "ignore_term"):
                # The parent must terminate blocking DNS and SIGTERM-resistant
                # work. No sockets, real DNS or workflow handlers are used.
                while True:
                    sleep(1)
            if kind == "worker_crash":
                os._exit(72)
            if kind == "truncated_ipc":
                os.write(connection.fileno(), struct.pack("!I", 1000) + b"{")
                return
            if kind == "truncated_header":
                os.write(connection.fileno(), b"\x00\x00")
                return
            if kind == "empty_ipc":
                return
            if kind == "forbidden_network":
                import socket
                socket.getaddrinfo("localhost", 80)
            if kind == "forbidden_sqlite":
                import sqlite3
                sqlite3.connect(":memory:")
            if kind == "forbidden_subprocess":
                import subprocess
                subprocess.run(["/bin/false"], check=False)
            if kind == "worker_exception":
                raise RuntimeError("FIXTURE_EXCEPTION_MUST_NOT_LEAK")
            if recipe["delay_s"] and kind != "delayed_exit":
                sleep(recipe["delay_s"])
            if kind == "public_workflow":
                # Only delivered public HTTP bytes enter this pure fixture.
                # No FaultSpec, parent callback, private oracle or Store is
                # transferred into the child process.
                from .p1_gateway import make_fake_client
                request = json.loads(base64.b64decode(payload["body_b64"], validate=True))
                raw = make_fake_client(follow_attacks=recipe["follow_attacks"]).create(
                    request, timeout_s=payload["timeout_s"])
                identity = uuid4().hex
                raw["id"] = "fixture-child-response-" + identity
                response = fake_http_response(raw=raw, headers={
                    "content-type": "application/json", "x-litellm-call-id": "fixture-child-call-" + identity})
            else:
                response = HTTPResponse(recipe["status"], recipe["headers"],
                                        base64.b64decode(recipe["body_b64"], validate=True))
        else:
            binding = P3Binding.from_dict(payload["binding"])
            permit = LiveRuntimePermit(**payload["permit"])
            request = HTTPRequest(payload["method"], payload["url"],
                                  base64.b64decode(payload["body_b64"], validate=True),
                                  payload["timeout_s"])
            response = StdlibHTTPSender().send(
                request, authorization=payload["authorization"],
                runtime_permit=permit, binding=binding)
            _reject_credential_echo(response, payload["authorization"])
        _emit(connection, _response_packet(response))
        if recipe is not None and recipe["kind"] == "delayed_exit":
            sleep(recipe["delay_s"])
    except P3HTTPError as exc:
        try:
            _emit(connection, {"kind": "error", "code": exc.code})
        except Exception:
            pass
    except (TimeoutError,):
        try:
            _emit(connection, {"kind": "error", "code": "P3_HTTP_TIMEOUT"})
        except Exception:
            pass
    except BaseException:
        # Child exception text may contain credentials. Only a stable code is
        # serialized; parent classifies the result as ambiguous consumption.
        try:
            _emit(connection, {"kind": "error", "code": "P3_NETWORK_ERROR"})
        except Exception:
            pass
    finally:
        connection.close()


def _read_packet(connection, process, deadline):
    """Bound every IPC byte read, including a child dying mid-frame."""
    descriptor = connection.fileno()
    os.set_blocking(descriptor, False)
    data, length = bytearray(), None
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return None, "P3_HTTP_TIMEOUT"
            if not selector.select(min(remaining, 0.05)):
                if not process.is_alive():
                    # A final readiness check avoids losing bytes already
                    # buffered when the child exits between select and poll.
                    if not selector.select(0):
                        return None, "P3_WORKER_IPC_ERROR" if data else "P3_WORKER_EXIT"
                continue
            try:
                chunk = os.read(descriptor, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                return None, "P3_WORKER_IPC_ERROR" if data else "P3_WORKER_EXIT"
            data.extend(chunk)
            if length is None and len(data) >= 4:
                length = struct.unpack("!I", data[:4])[0]
                if not 0 < length <= _MAX_FRAME_BYTES:
                    return None, "P3_WORKER_IPC_ERROR"
            if length is not None and len(data) >= length + 4:
                if len(data) != length + 4 or monotonic() >= deadline:
                    return None, "P3_HTTP_TIMEOUT" if monotonic() >= deadline else "P3_WORKER_IPC_ERROR"
                try:
                    packet = json.loads(bytes(data[4:]).decode("utf-8"))
                except (ValueError, UnicodeError, RecursionError):
                    return None, "P3_WORKER_IPC_ERROR"
                return packet, None
    finally:
        selector.close()


class BoundedHTTPSender:
    """One spawned child per send, with bounded termination and mandatory reap.

    ``recipes=None`` is the live sender and still requires the existing permit
    and explicit credential. A finite recipe sequence is visibly simulated.
    No request after a cleanup failure is permitted on the same sender.
    """

    def __init__(self, *, recipes=None, terminate_grace_s=2.0, cleanup_timeout_s=5.0):
        require(type(terminate_grace_s) in (int, float) and math.isfinite(terminate_grace_s)
                and type(cleanup_timeout_s) in (int, float) and math.isfinite(cleanup_timeout_s)
                and 0 < terminate_grace_s <= 2
                and terminate_grace_s <= cleanup_timeout_s <= 5,
                "Cleanup must fit the bounded five-second window", "P3_TRANSPORT_ERROR")
        require(recipes is None or (isinstance(recipes, (list, tuple))
                and all(type(r) is WireRecipe for r in recipes)),
                "Bounded fixtures require a finite explicit recipe list", "P3_FIXTURE_ERROR")
        self.simulated = recipes is not None
        self._recipes = None if recipes is None else list(recipes)
        self.terminate_grace_s = float(terminate_grace_s)
        self.cleanup_timeout_s = float(cleanup_timeout_s)
        self.request_count = 0
        self.cleanup_receipts = []
        self.fenced = False

    @property
    def real_request_count(self):
        # Count admitted live transport attempts, including a durable intent
        # that expired before a child could start. This is not a statement
        # that the provider received or billed that many requests.
        return 0 if self.simulated else self.request_count

    @property
    def last_receipt(self):
        return deepcopy(self.cleanup_receipts[-1]) if self.cleanup_receipts else None

    def _admit_receipt(self, request, deadline):
        self.request_count += 1
        receipt = {"schema_version": 1, "dispatch_index": self.request_count,
                   "simulated": self.simulated, "pid": None,
                   "process_start_method": "spawn", "timeout_s": request.timeout_s,
                   "elapsed_s": None, "deadline_expired": False, "worker_started": False,
                   "wire_result_received": False, "worker_error": None,
                   "termination_sent": False, "kill_sent": False, "reaped": False,
                   "exitcode": None, "cleanup_elapsed_s": 0.0, "cleanup_failed": False,
                   "local_cancel_only": True, "provider_cancelled": False,
                   "request_digest": hashlib.sha256(request.body).hexdigest(),
                   "worker_pid": None, "deadline_s": deadline, "finished_s": None,
                   "timed_out": False, "terminated": False, "killed": False,
                   "status": "starting", "late_result_ignored": False,
                   "unknown_consumption": True, "execution_phase": "spawn_worker"}
        self.cleanup_receipts.append(receipt)
        return receipt

    def _cleanup(self, process, receipt, *, terminate, request_deadline, injected_failure=False):
        started = monotonic()
        deadline = started + self.cleanup_timeout_s
        kill_reserve_s = min(0.25, self.cleanup_timeout_s * 0.2)
        try:
            if not terminate:
                # Returning a packet is not proof that Python has finished
                # exiting. Give normal exit its own opportunity rather than
                # misusing the (often much shorter) SIGTERM grace period.
                normal_wait_s = min(max(0.0, request_deadline - monotonic()),
                    max(0.0, self.cleanup_timeout_s - self.terminate_grace_s - kill_reserve_s))
                process.join(normal_wait_s)
            if process.is_alive():
                process.terminate()
                receipt["termination_sent"] = True
                process.join(max(0.0, min(self.terminate_grace_s,
                    deadline - monotonic() - kill_reserve_s)))
            if process.is_alive():
                process.kill()
                receipt["kill_sent"] = True
                process.join(max(0.0, deadline - monotonic()))
            receipt["reaped"] = not process.is_alive() and process.exitcode is not None
            receipt["exitcode"] = process.exitcode
            receipt["cleanup_failed"] = not receipt["reaped"] or injected_failure
        except Exception:
            receipt["cleanup_failed"] = True
            # Best effort only within the same deadline; no unbounded join.
            try:
                if process.is_alive():
                    process.kill()
                    receipt["kill_sent"] = True
                process.join(max(0.0, deadline - monotonic()))
                receipt["reaped"] = not process.is_alive() and process.exitcode is not None
                receipt["exitcode"] = process.exitcode
            except Exception:
                pass
        receipt["cleanup_elapsed_s"] = max(0.0, monotonic() - started)
        if receipt["cleanup_failed"]:
            self.fenced = True
        if receipt["reaped"]:
            process.close()

    def send(self, request, *, authorization=None, runtime_permit=None, binding=None,
             deadline_monotonic=None, intent_committed=False):
        global SPAWN_IN_PROGRESS
        require(not self.fenced, "A worker cleanup failure fences future sends", "P3_WORKER_FENCED")
        require(type(intent_committed) is bool,
                "Dispatch intent status must be an explicit boolean", "P3_TRANSPORT_ERROR")
        require(isinstance(request, HTTPRequest) and isinstance(binding, P3Binding)
                and request.method == "POST" and request.url == binding.endpoint + "/chat/completions"
                and isinstance(request.body, bytes) and type(request.timeout_s) in (int, float)
                and math.isfinite(request.timeout_s) and 0 < request.timeout_s <= binding.timeout_s
                and binding.simulated == self.simulated,
                "Bounded sender requires its exact admitted wire binding", "P3_TRANSPORT_ERROR")
        started = monotonic()
        if deadline_monotonic is None:
            deadline = started + request.timeout_s
        else:
            require(type(deadline_monotonic) in (int, float) and math.isfinite(deadline_monotonic)
                    and deadline_monotonic <= started + request.timeout_s + 0.001,
                    "Bounded worker cannot extend the parent deadline", "P3_TRANSPORT_ERROR")
            deadline = deadline_monotonic
        if deadline <= started:
            if not intent_committed:
                raise P3HTTPError("P3_HTTP_TIMEOUT", dispatched=False, ambiguous=False)
            # before_send has already committed a durable dispatch intent.
            # Observe that admitted attempt consistently without creating a
            # process, consuming a fixture or sending any provider traffic.
            receipt = self._admit_receipt(request, deadline)
            finished = monotonic()
            receipt.update(elapsed_s=max(0.0, finished - started), finished_s=finished,
                deadline_expired=True, timed_out=True, reaped=True,
                worker_error="P3_HTTP_TIMEOUT", status="timeout",
                execution_phase="preworker_deadline_abort")
            exception = P3HTTPError("P3_HTTP_TIMEOUT", dispatched=True, ambiguous=True)
            exception.cleanup_receipt = deepcopy(receipt)
            raise exception
        if not self.simulated:
            require(isinstance(runtime_permit, LiveRuntimePermit),
                    "Live worker needs a runtime authorization", "P3_LIVE_DISABLED")
            runtime_permit.validate(binding)
            require(isinstance(authorization, str) and bool(authorization)
                    and "\r" not in authorization and "\n" not in authorization,
                    "Live worker needs an explicit credential", "P3_CREDENTIAL_ERROR")
        recipe, recipe_payload = None, None
        if self.simulated:
            require(bool(self._recipes), "No finite worker recipe remains", "P3_FIXTURE_ERROR")
            recipe = self._recipes.pop(0)
            response = recipe.response or HTTPResponse(200, {}, b"{}")
            recipe_payload = {"kind": recipe.kind, "delay_s": recipe.delay_s,
                              "follow_attacks": recipe.follow_attacks,
                              "status": response.status, "headers": deepcopy(response.headers),
                              "body_b64": base64.b64encode(response.body).decode("ascii")}
        payload = {"method": request.method, "url": request.url,
                   "body_b64": base64.b64encode(request.body).decode("ascii"),
                   "timeout_s": min(request.timeout_s, max(0.000001, deadline - monotonic())),
                   "binding": binding.to_dict(),
                   "permit": asdict(runtime_permit) if runtime_permit is not None else None,
                   "authorization": authorization if not self.simulated else None}
        receipt = self._admit_receipt(request, deadline)
        context = multiprocessing.get_context("spawn")
        receiver, writer = context.Pipe(duplex=False)
        process = context.Process(target=_worker, args=(writer, payload, recipe_payload),
                                  name="p3-wire-worker", daemon=True)
        packet, error = None, None
        try:
            try:
                SPAWN_IN_PROGRESS = True
                process.start()
                receipt.update({"pid": process.pid, "worker_pid": process.pid,
                                "worker_started": True, "execution_phase": "worker_http"})
            except Exception:
                error = "P3_WORKER_START_ERROR"
                receipt["worker_error"] = error
                receipt["status"] = "worker_error"
                receipt["reaped"] = True  # No child was created; nothing remains.
            finally:
                SPAWN_IN_PROGRESS = False
                writer.close()
            if receipt["worker_started"]:
                try:
                    packet, error = _read_packet(receiver, process, deadline)
                except Exception:
                    packet, error = None, "P3_WORKER_IPC_ERROR"
                receipt["wire_result_received"] = packet is not None
                receipt["worker_error"] = error
        finally:
            if receipt["worker_started"]:
                self._cleanup(process, receipt, terminate=error is not None,
                              request_deadline=deadline,
                              injected_failure=recipe is not None and recipe.kind == "cleanup_failure")
                if error == "P3_HTTP_TIMEOUT":
                    try:
                        os.set_blocking(receiver.fileno(), False)
                        # A bounded nonblocking drain records a response that
                        # arrived during cleanup. It is never parsed/published.
                        receipt["late_result_ignored"] = bool(os.read(receiver.fileno(), 65536))
                    except (BlockingIOError, OSError):
                        pass
            receiver.close()
            finished = monotonic()
            receipt["elapsed_s"] = max(0.0, finished - started)
            receipt["finished_s"] = finished
            receipt["deadline_expired"] = finished >= deadline
            receipt["terminated"] = receipt["termination_sent"]
            receipt["killed"] = receipt["kill_sent"]
            receipt["execution_phase"] = "cleanup_complete" if not receipt["cleanup_failed"] else "cleanup_failed"
        if receipt["cleanup_failed"]:
            error = "P3_WORKER_CLEANUP_ERROR"
        elif receipt["deadline_expired"]:
            error = "P3_HTTP_TIMEOUT"
            receipt["deadline_expired"] = True
        elif error is None and receipt["exitcode"] != 0:
            error = "P3_WORKER_EXIT"
        elif error is None:
            if not isinstance(packet, dict) or packet.get("kind") not in ("response", "error"):
                error = "P3_WORKER_IPC_ERROR"
            elif packet["kind"] == "error":
                error = packet.get("code") if packet.get("code") in {
                    "P3_HTTP_TIMEOUT", "P3_NETWORK_ERROR", "P3_RESPONSE_TOO_LARGE"} else "P3_NETWORK_ERROR"
        receipt["timed_out"] = receipt["deadline_expired"] or error == "P3_HTTP_TIMEOUT"
        receipt["late_result_ignored"] = receipt["late_result_ignored"] or (packet is not None and receipt["timed_out"])
        receipt["status"] = ("cleanup_error" if receipt["cleanup_failed"] else
                             "timeout" if receipt["timed_out"] else
                             "worker_error" if error is not None else "response")
        receipt["unknown_consumption"] = error is not None
        if error is not None:
            receipt["worker_error"] = error
            exception = P3HTTPError(error, dispatched=True, ambiguous=True)
            exception.cleanup_receipt = deepcopy(receipt)
            raise exception
        try:
            require(set(packet) == {"kind", "status", "headers", "body_b64"}
                    and type(packet["status"]) is int and isinstance(packet["headers"], dict),
                    "Worker returned an invalid wire envelope", "P3_WORKER_IPC_ERROR")
            response = HTTPResponse(packet["status"], packet["headers"],
                                    base64.b64decode(packet["body_b64"], validate=True))
            require(len(response.body) <= _MAX_BODY_BYTES,
                    "Worker response exceeds cap", "P3_WORKER_IPC_ERROR")
        except (ContractError, ValueError, TypeError):
            finished = monotonic()
            code = "P3_HTTP_TIMEOUT" if finished >= deadline else "P3_WORKER_IPC_ERROR"
            receipt.update(worker_error=code, status="timeout" if code == "P3_HTTP_TIMEOUT" else "worker_error",
                           unknown_consumption=True, deadline_expired=finished >= deadline,
                           timed_out=code == "P3_HTTP_TIMEOUT", finished_s=finished,
                           elapsed_s=max(0.0, finished - started))
            exception = P3HTTPError(code, dispatched=True)
            exception.cleanup_receipt = deepcopy(receipt)
            raise exception from None
        finished = monotonic()
        receipt.update(finished_s=finished, elapsed_s=max(0.0, finished - started),
                       deadline_expired=finished >= deadline)
        if receipt["deadline_expired"]:
            receipt.update(worker_error="P3_HTTP_TIMEOUT", status="timeout", timed_out=True,
                           unknown_consumption=True, late_result_ignored=True)
            exception = P3HTTPError("P3_HTTP_TIMEOUT", dispatched=True)
            exception.cleanup_receipt = deepcopy(receipt)
            raise exception
        return response
