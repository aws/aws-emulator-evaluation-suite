"""update-ipset-nonexistent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-ipset-nonexistent-rejected"
GROUP = 'ipset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (code, message) of the first NON-transient failure; an unexpected success
    raises. Transient WAFv2 codes are retried rather than reported, so an assertion about
    a semantic error is never polluted by throttling or propagation delay."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            err = resp.get("Error", {}) if isinstance(resp, dict) else {}
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message")
            time.sleep(delay)
            continue
        raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")
    raise AssertionError("unreachable: attempts must be positive")

_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIPSet on a real IPSet lands and advances the LockToken; UpdateIPSet and GetIPSet on a
    never-created Id both fail with WAFNonexistentItemException and the exact not-found message.
    """
    w = ctx.client("wafv2")

    real_name = ctx.unique_name("sim2real-behav-waf-real-")
    created = w.create_ip_set(
        Name=real_name,
        Scope=SCOPE,
        IPAddressVersion="IPV4",
        Addresses=["10.1.0.0/24"],
    )
    real_id = created["Summary"]["Id"]
    real_token = created["Summary"]["LockToken"]

    def _cleanup():
        try:
            cur = w.get_ip_set(Name=real_name, Scope=SCOPE, Id=real_id)
            w.delete_ip_set(Name=real_name, Scope=SCOPE, Id=real_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: an update against the real IPSet succeeds, so the account
    # and credentials are healthy for this operation.
    positive = w.update_ip_set(
        Name=real_name, Scope=SCOPE, Id=real_id, Addresses=["10.2.0.0/24"], LockToken=real_token
    )
    assert positive["NextLockToken"] != real_token
    after_positive = w.get_ip_set(Name=real_name, Scope=SCOPE, Id=real_id)
    assert after_positive["IPSet"]["Addresses"] == ["10.2.0.0/24"], after_positive["IPSet"]["Addresses"]

    # Break exactly one thing: target an Id/Name pair that was never created.
    ghost_name = ctx.unique_name("sim2real-behav-waf-ghost-")
    ghost_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error_stable(
        lambda: w.update_ip_set(
            Name=ghost_name,
            Scope=SCOPE,
            Id=ghost_id,
            Addresses=["192.0.2.4/32"],
            LockToken=ghost_id,
        )
    )
    assert code == "WAFNonexistentItemException", code
    assert message == _NOT_FOUND_MESSAGE, message

    # Terminal read: an independent GetIPSet (a different operation than the
    # rejected UpdateIPSet) confirms the ghost id is genuinely absent, not just
    # that the mutating call happened to raise.
    read_code, read_message = _error_stable(
        lambda: w.get_ip_set(Name=ghost_name, Scope=SCOPE, Id=ghost_id)
    )
    assert read_code == "WAFNonexistentItemException", read_code
    assert read_message == _NOT_FOUND_MESSAGE, read_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
