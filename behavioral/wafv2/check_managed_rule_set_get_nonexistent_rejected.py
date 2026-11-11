"""managed-rule-set-get-nonexistent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "managed-rule-set-get-nonexistent-rejected"
GROUP = 'managed-rule-sets'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"
_NOT_FOUND = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

def _error_detail_stable(fn, attempts=10, delay=6.0):
    """Return (code, message) of the first NON-transient failure, or (None, None) on
    success. Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error code is never polluted by throttling or propagation delay."""
    for attempt in range(attempts):
        try:
            fn()
            return None, None
        except Exception as exc:  # noqa: BLE001
            code = ""
            message = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                error = resp.get("Error", {})
                code = error.get("Code", "")
                message = error.get("Message", "")
            if code and code not in _TRANSIENT_CODES:
                return code, message
            if not code:
                raise
            if attempt == attempts - 1:
                return code, message
            time.sleep(delay)
    return None, None

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListManagedRuleSets returns an empty list for an account that is not a managed rule group vendor,
    and GetManagedRuleSet for an unowned Id fails with WAFNonexistentItemException and the exact
    not-found message.
    """
    w = ctx.client("wafv2")
    listed = _retry_transient(lambda: w.list_managed_rule_sets(Scope=SCOPE, Limit=10))
    owned = listed["ManagedRuleSets"]
    assert isinstance(owned, list), f"expected ManagedRuleSets to be a list, got {owned!r}"
    assert owned == [], (
        f"expected this non-vendor account to own zero ManagedRuleSets, got {owned!r} "
        "-- the premise that GetManagedRuleSet below targets an unowned resource no "
        "longer holds"
    )

    code, message = _error_detail_stable(
        lambda: w.get_managed_rule_set(
            Name=ctx.unique_name("sim2real-behav-waf-mrs-"),
            Scope=SCOPE,
            Id="00000000-0000-0000-0000-000000000000",
        )
    )
    assert code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException, got {code!r} (message={message!r})"
    )
    assert message == _NOT_FOUND, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
