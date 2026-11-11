"""update-managed-rule-set-version-expiry-nonexistent-version-rejected."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-managed-rule-set-version-expiry-nonexistent-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]


_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateManagedRuleSetVersionExpiryDate on a nonexistent ManagedRuleSet fails NonexistentItem.

    Update and GetManagedRuleSet both fail WAFNonexistentItemException with the exact message, and
    ListManagedRuleSets omits the id; ListAvailableManagedRuleGroups is the healthy-account control.
    """
    wafv2 = ctx.client("wafv2")

    fake_name = re.sub(r"[^\w\-]", "-", ctx.unique_name("sim2real-wafv2-mrs-"))
    fake_id = str(uuid.uuid4())
    fake_lock_token = str(uuid.uuid4())
    expiry = datetime.now(timezone.utc) + timedelta(days=1)

    code, message = _error_code(
        lambda: wafv2.update_managed_rule_set_version_expiry_date(
            Name=fake_name,
            Scope="REGIONAL",
            Id=fake_id,
            LockToken=fake_lock_token,
            VersionToExpire="1.0",
            ExpiryTimestamp=expiry,
        )
    )
    assert code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException for a fabricated ManagedRuleSet, got {code!r}"
    )
    assert message == _NOT_FOUND_MESSAGE, message

    # Independent read at the same identity, through a different operation: a fake
    # ManagedRuleSet must be unreachable by Get too, not just rejected on Update.
    get_code, get_message = _error_code(
        lambda: wafv2.get_managed_rule_set(Name=fake_name, Scope="REGIONAL", Id=fake_id)
    )
    assert get_code == "WAFNonexistentItemException", (
        f"GetManagedRuleSet on the same fabricated id: expected WAFNonexistentItemException, "
        f"got {get_code!r}"
    )
    assert get_message == _NOT_FOUND_MESSAGE, get_message

    # Effect absent: nothing was created/scheduled under the target identity.
    listed = wafv2.list_managed_rule_sets(Scope="REGIONAL")["ManagedRuleSets"]
    assert not any(m["Id"] == fake_id or m["Name"] == fake_name for m in listed), (
        f"fabricated id {fake_id!r} / name {fake_name!r} must not appear in "
        "ListManagedRuleSets after the rejected update"
    )

    # Positive control, same file: a real, always-available read on the WAFv2 managed
    # rule group catalog still succeeds -- the rejection above is target-specific, not
    # an account-wide failure.
    available = wafv2.list_available_managed_rule_groups(Scope="REGIONAL")["ManagedRuleGroups"]
    assert len(available) > 0, (
        "ListAvailableManagedRuleGroups returned zero groups -- the account/credentials "
        "used for the positive control look unhealthy, not just the fabricated resource"
    )


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
