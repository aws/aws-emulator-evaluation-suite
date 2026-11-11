"""account-properties-toggle-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-properties-toggle-persists"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iam-account-properties")
def run(ctx) -> None:
    """PutAccountProperties durably updates an account-level server-side flag
    (RoleManager/Enabled) that is immediately and consistently readable via
    GetAccountProperties, in both directions of the toggle."""
    iam = ctx.client("iam")
    key = "RoleManager/Enabled"

    original = iam.get_account_properties()["Properties"].get(key)
    ctx.on_cleanup(lambda: iam.put_account_properties(Properties={key: original or "false"}))

    iam.put_account_properties(Properties={key: "true"})
    after_true = iam.get_account_properties()["Properties"]
    assert after_true[key] == "true", f"expected {key}='true' after put, got {after_true.get(key)!r}"

    iam.put_account_properties(Properties={key: "false"})
    after_false = iam.get_account_properties()["Properties"]
    assert after_false[key] == "false", f"expected {key}='false' after put, got {after_false.get(key)!r}"

    if original is not None:
        iam.put_account_properties(Properties={key: original})
        restored = iam.get_account_properties()["Properties"]
        assert restored[key] == original, f"expected {key}={original!r} after restore, got {restored.get(key)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
