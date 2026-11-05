"""School API only; no retries or credentials in saved headers."""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from .core import encode, utc


MODEL = 'api-glm-5.3-flash'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Gateway:
    def __init__(self, ledger, budget, model=MODEL):
        self.ledger, self.budget, self.model = ledger, budget, model
        self.key = os.environ.get('OPENAI_API_KEY') or os.environ.get('TRITONAI_API_KEY', '')
        self.base = os.environ.get('OPENAI_BASE_URL', '').rstrip('/')
        parsed = urllib.parse.urlsplit(self.base)
        if (parsed.scheme != 'https' or parsed.hostname != 'tritonai-api.ucsd.edu'
                or parsed.path != '/v1' or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError('Set OPENAI_BASE_URL=https://tritonai-api.ucsd.edu/v1')
        if not self.key:
            raise ValueError('API credentials missing; use environment variables, never paste a key')
        ledger.secret = self.key
        self.calls = []
        self.opener = urllib.request.build_opener(NoRedirect())

    def check(self):
        request = urllib.request.Request(self.base + '/models',
            headers={'Authorization': 'Bearer ' + self.key})
        with self.opener.open(request, timeout=min(30, self.budget.remaining())) as response:
            result = json.load(response)
        return self.model in {x['id'] for x in result.get('data', [])}

    def complete(self, actor, messages, source_ids, branch, tools=None):
        payload = {'model': self.model, 'messages': messages, 'temperature': 0,
            'reasoning_effort': 'low', 'max_completion_tokens': 2048, 'stream': False}
        if tools:
            payload.update(tools=tools, tool_choice={
                'type': 'function', 'function': {'name': tools[0]['function']['name']}})
        data = encode(payload)
        if len(data) > 100_000:
            raise ValueError('Request exceeds local 100KB cap; not sent')
        self.budget.reserve()
        call_id = 'call_%03d' % self.budget.calls
        record = {'id': call_id, 'actor': actor, 'branch': branch, 'started': utc(),
            'source_ids': list(source_ids), 'usage': None, 'status': 'dispatching',
            'request_bytes': len(data)}
        self.calls.append(record)
        self.ledger.write('calls/' + call_id + '.request.json', payload)
        self.ledger.write('calls.json', self.calls)
        self.ledger.event('model_context', call_id=call_id, actor=actor, branch=branch,
                          artifact_ids=list(source_ids))
        request = urllib.request.Request(self.base + '/chat/completions', data=data, method='POST',
            headers={'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json'})
        start = time.monotonic()
        try:
            with self.opener.open(request, timeout=min(90, self.budget.remaining())) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise RuntimeError('API response exceeds size cap')
            text = raw.decode().replace(self.key, '[REDACTED]')
            body = json.loads(text)
            self.ledger.write('calls/' + call_id + '.response.json', body)
            reported = body.get('usage')
            record['reported_usage'] = reported
            fields = ('prompt_tokens', 'completion_tokens', 'total_tokens')
            record['usage'] = reported if (isinstance(reported, dict) and all(
                isinstance(reported.get(k), int) and not isinstance(reported[k], bool)
                and reported[k] >= 0 for k in fields)) else None
            record['response_model'] = body.get('model')
            choice = body['choices'][0]
            record['finish_reason'] = choice.get('finish_reason')
            record['status'] = 'received'
            if choice.get('finish_reason') in ('length', 'content_filter'):
                raise RuntimeError('Truncated/filtered model output; no retry')
            return choice['message'], call_id
        except urllib.error.HTTPError as exc:
            record['status'] = 'http_error'
            record['http_status'] = exc.code
            self.ledger.write('calls/' + call_id + '.error.json', {
                'status': exc.code, 'message': exc.read(4096).decode(errors='replace')})
            raise RuntimeError('HTTP %s; no retry; usage may be unknown' % exc.code) from None
        except Exception:
            if record['status'] == 'dispatching':
                record['status'] = 'unknown_outcome'
            raise
        finally:
            record['latency_seconds'] = time.monotonic() - start
            self.ledger.write('calls.json', self.calls)
