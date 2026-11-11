"""op-contract-put-account-properties."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-put-account-properties"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-account-properties")
def run(ctx) -> None:
    """PutAccountProperties flips the RoleManager/Enabled account property; observable via GetAccountProperties."""
    iam = ctx.client("iam")

    original = iam.get_account_properties().get("Properties", {})
    original_value = original.get("RoleManager/Enabled", "false")
    toggled_value = "false" if original_value == "true" else "true"

    def _restore():
        iam.put_account_properties(Properties={"RoleManager/Enabled": original_value})

    ctx.on_cleanup(_restore)

    iam.put_account_properties(Properties={"RoleManager/Enabled": toggled_value})

    def _probe():
        return iam.get_account_properties().get("Properties", {}).get("RoleManager/Enabled")

    observed = _poll_until(_probe, lambda v: v == toggled_value, timeout_s=30, interval_s=1.5)
    assert observed == toggled_value, f"RoleManager/Enabled did not converge to {toggled_value!r}, saw {observed!r}"

    # Error boundary: the Properties key pattern (^[A-Za-z][A-Za-z0-9/_-]*$) is enforced as a
    # modeled request-shape constraint, so a key that violates it is rejected with ValidationError
    # (the real IAM wire error code has no "Exception" suffix), not a business-logic InvalidInput.
    bad_key = "  not a valid key  "
    code, message = _error_code(lambda: iam.put_account_properties(Properties={bad_key: "true"}))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = (
        "1 validation error detected: Value at 'properties' failed to satisfy constraint: Map keys "
        "must satisfy constraint: [Member must have length less than or equal to 50, Member must "
        "have length greater than or equal to 1, Member must satisfy regular expression pattern: "
        "^[A-Za-z][A-Za-z0-9/_-]*$]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent, via an independent read at the destination: the rejected write neither
    # persisted the bad key nor disturbed the toggle the earlier, successful put made.
    after_bad_key = iam.get_account_properties().get("Properties", {})
    assert bad_key not in after_bad_key, f"rejected write leaked into account properties: {after_bad_key}"
    assert after_bad_key.get("RoleManager/Enabled") == toggled_value, (
        f"rejected malformed-key write disturbed RoleManager/Enabled: {after_bad_key}"
    )


# ===== helpers =====
def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
