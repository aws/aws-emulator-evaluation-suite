"""put-managed-rule-set-versions-invalid-version-format-rejected."""
from __future__ import annotations

import re
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-managed-rule-set-versions-invalid-version-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a target that does not exist.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedRuleSetVersions on a nonexistent ManagedRuleSet fails WAFNonexistentItemException
    with the exact message and publishes nothing; ListAvailableManagedRuleGroups is the control."""
    wafv2 = ctx.client("wafv2")

    # Positive control, same file: a real, always-available read on the WAFv2 managed
    # rule group catalog succeeds -- the rejection below is target-specific, not an
    # account-wide failure.
    available = wafv2.list_available_managed_rule_groups(Scope="REGIONAL")["ManagedRuleGroups"]
    assert len(available) > 0

    fake_name = re.sub(r"[^\w\-]", "-", ctx.unique_name("sim2real-wafv2-mrs-"))
    fake_id = str(uuid.uuid4())
    fake_lock_token = str(uuid.uuid4())
    account = ctx.client("sts").get_caller_identity()["Account"]

    code, message = _error(
        lambda: wafv2.put_managed_rule_set_versions(
            Name=fake_name,
            Scope="REGIONAL",
            Id=fake_id,
            LockToken=fake_lock_token,
            VersionsToPublish={
                "1.0": {
                    "AssociatedRuleGroupArn": (
                        f"arn:aws:wafv2:{ctx.region}:{account}:regional/rulegroup/"
                        "sim2real-nonexistent/00000000-0000-0000-0000-000000000000"
                    )
                }
            },
        )
    )
    assert code == "WAFNonexistentItemException", f"got {code!r} instead"
    assert message == NONEXISTENT_MESSAGE, message

    # Effect absent: nothing was published/created under the target identity.
    listed = wafv2.list_managed_rule_sets(Scope="REGIONAL")["ManagedRuleSets"]
    assert not any(m["Id"] == fake_id or m["Name"] == fake_name for m in listed)



def _error(fn):
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
