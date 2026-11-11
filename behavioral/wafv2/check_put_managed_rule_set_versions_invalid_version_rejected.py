"""put-managed-rule-set-versions-invalid-version-rejected."""
from __future__ import annotations

import re
import uuid
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-managed-rule-set-versions-invalid-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a resource that does not exist.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedRuleSetVersions rejects a malformed VersionsToPublish key with a ValidationException
    before checking the (nonexistent) rule set exists; GetManagedRuleSet on an unknown Id fails
    with WAFNonexistentItemException.
    """
    wafv2 = ctx.client("wafv2")

    bogus_id = str(uuid.uuid4())
    code, message = _error(
        lambda: wafv2.get_managed_rule_set(
            Name="sim2real-nonexistent-managed-rule-set", Scope="REGIONAL", Id=bogus_id
        )
    )
    assert code == "WAFNonexistentItemException", f"got {code!r} instead"
    assert message == NONEXISTENT_MESSAGE, message

    # ManagedRuleSets are vendor-owned and cannot be created, so the target is necessarily fake;
    # the rule group ARN is well formed, so the version key is the only malformed input.
    fake_name = re.sub(r"[^\w\-]", "-", ctx.unique_name("sim2real-wafv2-mrs-"))
    fake_id = str(uuid.uuid4())
    fake_lock_token = str(uuid.uuid4())
    account = ctx.client("sts").get_caller_identity()["Account"]
    rule_group_arn = (
        f"arn:aws:wafv2:{ctx.region}:{account}:regional/rulegroup/"
        "sim2real-nonexistent/00000000-0000-0000-0000-000000000000"
    )
    bad_key = "not a valid version!!"
    invalid_version_code, invalid_version_message = _error(
        lambda: wafv2.put_managed_rule_set_versions(
            Name=fake_name,
            Scope="REGIONAL",
            Id=fake_id,
            LockToken=fake_lock_token,
            VersionsToPublish={bad_key: {"AssociatedRuleGroupArn": rule_group_arn}},
        )
    )
    assert invalid_version_code == "ValidationException", (
        f"got {invalid_version_code!r} instead"
    )
    assert invalid_version_message == (
        "1 validation error detected: Value '{" + bad_key + "=VersionToPublish("
        "associatedRuleGroupArn=" + rule_group_arn + ", forecastedLifetime=null)}' at "
        "'versionsToPublish' failed to satisfy constraint: Map keys must satisfy "
        "constraint: [Member must have length less than or equal to 64, Member must have "
        "length greater than or equal to 1, Member must satisfy regular expression "
        "pattern: ^[\\w#:\\.\\-/]+$]"
    ), invalid_version_message

    # Nothing was published under the target identity.
    listed = wafv2.list_managed_rule_sets(Scope="REGIONAL")["ManagedRuleSets"]
    assert not any(m["Id"] == fake_id or m["Name"] == fake_name for m in listed)

    # Positive control: the rejection is target-specific, not an account-wide failure.
    available = wafv2.list_available_managed_rule_groups(Scope="REGIONAL")["ManagedRuleGroups"]
    assert len(available) > 0


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn raises. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
