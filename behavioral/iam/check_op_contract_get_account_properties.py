"""op-contract-getAccountProperties."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getAccountProperties"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-account-properties")
def run(ctx) -> None:
    """GetAccountProperties reflects a well-formed PutAccountProperties write; a
    malformed key fails with ValidationError and its exact message, is not
    stored, and leaves the earlier write in place."""
    iam = ctx.client("iam")

    before = iam.get_account_properties()
    assert isinstance(before.get("Properties"), dict)

    # Positive control: a well-formed write to the one documented account
    # property succeeds and is reflected, before we lean on a rejection.
    original_value = before["Properties"].get("RoleManager/Enabled", "false")
    toggled_value = "false" if original_value == "true" else "true"
    ctx.on_cleanup(lambda: iam.put_account_properties(Properties={"RoleManager/Enabled": original_value}))

    iam.put_account_properties(Properties={"RoleManager/Enabled": toggled_value})
    after_toggle = iam.get_account_properties()["Properties"]
    assert after_toggle.get("RoleManager/Enabled") == toggled_value, (
        f"positive control failed: expected RoleManager/Enabled={toggled_value!r}, got {after_toggle}"
    )

    # Key pattern requires ^[A-Za-z][A-Za-z0-9/_-]*$ -- a key starting with a
    # space and containing spaces violates this.
    bad_key = "  not a valid key  "
    code, message = _error(lambda: iam.put_account_properties(Properties={bad_key: "true"}))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'properties' failed to satisfy constraint: "
        "Map keys must satisfy constraint: [Member must have length less than or equal to 50, "
        "Member must have length greater than or equal to 1, "
        "Member must satisfy regular expression pattern: ^[A-Za-z][A-Za-z0-9/_-]*$]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = iam.get_account_properties()
    assert isinstance(after.get("Properties"), dict)
    assert bad_key not in after["Properties"], "rejected write leaked into account properties"
    assert after["Properties"].get("RoleManager/Enabled") == toggled_value, (
        f"rejected malformed-key write disturbed RoleManager/Enabled: {after['Properties']}"
    )

    iam.put_account_properties(Properties={"RoleManager/Enabled": original_value})
    restored = iam.get_account_properties()["Properties"]
    assert restored.get("RoleManager/Enabled") == original_value, (
        f"expected restore to RoleManager/Enabled={original_value!r}, got {restored}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
