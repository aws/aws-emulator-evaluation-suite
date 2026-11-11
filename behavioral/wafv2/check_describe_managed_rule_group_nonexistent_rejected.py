"""describe-managed-rule-group-nonexistent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-managed-rule-group-nonexistent-rejected"
GROUP = 'managed-rule-groups'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=10, delay=6.0):
    """Call fn, retrying WAFv2's transient control-plane errors. Any other exception
    (including the specific rejection this check exists to observe) is raised immediately."""
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                raise
            time.sleep(delay)

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (code, message) of the first NON-transient failure. Transient WAFv2 codes
    are retried rather than reported, so an assertion about a semantic error is never
    polluted by throttling or propagation delay. A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            code, message = "", ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
                message = resp.get("Error", {}).get("Message", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, message
            time.sleep(delay)
        else:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeManagedRuleGroup returns a real AWS managed rule group with Capacity > 0 and fails
    with WAFNonexistentItemException and the exact message for a group name that does not exist.
    """
    w = ctx.client("wafv2")

    real = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE
    ))
    assert real.get("Capacity", 0) > 0, real

    code, message = _error_stable(
        lambda: w.describe_managed_rule_group(
            VendorName="AWS", Name="AWSManagedRulesNoSuchRuleSet", Scope=SCOPE
        )
    )
    assert code == "WAFNonexistentItemException", code
    assert message == (
        "ManagedRules with name AWSManagedRulesNoSuchRuleSet by vendor AWS does not exist. "
        "Please check your inputs."
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
