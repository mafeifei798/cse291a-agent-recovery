"""Finite public-message HTTP fixtures for the supervised development entry."""
from .contracts import require
from .p3_deadline import BoundedHTTPSender, WireRecipe
from .p3_transport import P3HTTPClient


def bounded_fixture_client(binding, *, follow_attacks=False, recipes=None,
                           terminate_grace_s=2.0, cleanup_timeout_s=5.0):
    require(binding.simulated and not binding.real_requests_authorized,
            "Fixture factory cannot use a live binding", "OFFLINE_ONLY")
    if recipes is None:
        recipes = [WireRecipe("public_workflow", follow_attacks=follow_attacks)] * 5
    sender = BoundedHTTPSender(recipes=recipes, terminate_grace_s=terminate_grace_s,
                               cleanup_timeout_s=cleanup_timeout_s)
    return P3HTTPClient(binding, sender)
