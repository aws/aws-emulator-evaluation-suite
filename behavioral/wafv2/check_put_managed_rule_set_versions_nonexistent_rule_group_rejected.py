"""put-managed-rule-set-versions-nonexistent-rule-group-rejected."""
from __future__ import annotations

import re
import uuid
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-managed-rule-set-versions-nonexistent-rule-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]

_SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a target that does not exist.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedRuleSetVersions naming a nonexistent AssociatedRuleGroupArn fails with
    WAFNonexistentItemException and the exact not-found message, the target ManagedRuleSet is not
    listed, and the available managed rule group catalog is non-empty.
    """
    wafv2 = ctx.client("wafv2")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_name = re.sub(r"[^\w\-]", "-", ctx.unique_name("sim2real-wafv2-mrs-"))
    fake_id = str(uuid.uuid4())
    fake_lock_token = str(uuid.uuid4())
    nonexistent_rule_group_arn = (
        f"arn:aws:wafv2:{ctx.region}:{account_id}:regional/rulegroup/"
        f"sim2real-behav-nonexistent-rule-group/{uuid.uuid4()}"
    )

    code, message = _error(
        lambda: wafv2.put_managed_rule_set_versions(
            Name=fake_name,
            Scope=_SCOPE,
            Id=fake_id,
            LockToken=fake_lock_token,
            VersionsToPublish={
                "1.0": {"AssociatedRuleGroupArn": nonexistent_rule_group_arn},
            },
        )
    )
    assert code == "WAFNonexistentItemException", f"got {code!r} instead"
    assert message == NONEXISTENT_MESSAGE, message

    # Effect absent: nothing was published/created under the target identity.
    listed = wafv2.list_managed_rule_sets(Scope=_SCOPE)["ManagedRuleSets"]
    assert not any(m["Id"] == fake_id or m["Name"] == fake_name for m in listed), (
        "the fake ManagedRuleSet must not appear in ListManagedRuleSets after the rejected call"
    )

    # Positive control, same file: a real, always-available read on the WAFv2 managed
    # rule group catalog still succeeds -- the rejection above is target-specific, not
    # an account-wide failure.
    available = wafv2.list_available_managed_rule_groups(Scope=_SCOPE)["ManagedRuleGroups"]
    assert len(available) > 0, "expected the AWS-vendored managed rule group catalog to be non-empty"


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
