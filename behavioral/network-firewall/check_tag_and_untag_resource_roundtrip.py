"""tag-and-untag-resource-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-roundtrip"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource tags appear in ListTagsForResource and UntagResource removes only the named keys;
    after DeleteRuleGroup, DescribeRuleGroup and a further mutation both answer
    ResourceNotFoundException with the exact message."""
    nfw = ctx.client("network-firewall")

    rg_name = ctx.unique_name("sim2real-nfw-rg-")
    created = nfw.create_rule_group(
        RuleGroupName=rg_name, Type="STATEFUL", Capacity=10,
        RuleGroup={"RulesSource": {"StatefulRules": [{
            "Action": "ALERT",
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "ANY", "Destination": "ANY", "DestinationPort": "ANY"},
            "RuleOptions": [{"Keyword": "sid:1"}],
        }]}},
        Tags=[{"Key": "sim2real:keep", "Value": "yes"}],
    )
    rule_group_arn = created["RuleGroupResponse"]["RuleGroupArn"]

    def _cleanup():
        try:
            nfw.delete_rule_group(RuleGroupArn=rule_group_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    nfw.tag_resource(ResourceArn=rule_group_arn, Tags=[
        {"Key": "sim2real:temp-a", "Value": "1"}, {"Key": "sim2real:temp-b", "Value": "2"},
    ])
    rg_tags = {t["Key"]: t["Value"] for t in nfw.list_tags_for_resource(ResourceArn=rule_group_arn)["Tags"]}
    assert rg_tags["sim2real:keep"] == "yes", f"expected sim2real:keep=yes, got {rg_tags.get('sim2real:keep')!r}"
    assert rg_tags["sim2real:temp-a"] == "1", f"expected sim2real:temp-a=1, got {rg_tags.get('sim2real:temp-a')!r}"
    assert rg_tags["sim2real:temp-b"] == "2", f"expected sim2real:temp-b=2, got {rg_tags.get('sim2real:temp-b')!r}"

    nfw.untag_resource(ResourceArn=rule_group_arn, TagKeys=["sim2real:temp-a", "sim2real:temp-b"])
    tags_after = {t["Key"]: t["Value"] for t in nfw.list_tags_for_resource(ResourceArn=rule_group_arn)["Tags"]}
    assert "sim2real:temp-a" not in tags_after, f"expected sim2real:temp-a removed, still present: {tags_after}"
    assert "sim2real:temp-b" not in tags_after, f"expected sim2real:temp-b removed, still present: {tags_after}"
    assert tags_after["sim2real:keep"] == "yes", \
        f"expected sim2real:keep=yes to survive untag, got {tags_after.get('sim2real:keep')!r}"

    nfw.delete_rule_group(RuleGroupArn=rule_group_arn)

    # DeleteRuleGroup completes asynchronously, so DescribeRuleGroup is awaited within a bounded
    # window rather than asserted on the first read. ListTagsForResource does NOT validate the
    # ARN against live rule groups -- it kept resolving the tags of a deleted rule group with no
    # error for the whole window, so DescribeRuleGroup is the read that
    # actually tracks resource existence here.
    deadline = time.monotonic() + 240
    read_code = read_message = None
    last_status = None
    while time.monotonic() < deadline:
        try:
            desc = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
            last_status = desc["RuleGroupResponse"]["RuleGroupStatus"]
            read_code = read_message = None
        except ClientError as e:
            read_code, read_message = e.response["Error"]["Code"], e.response["Error"].get("Message")
            if read_code == "ResourceNotFoundException":
                break
        time.sleep(2)
    assert read_code == "ResourceNotFoundException", (
        f"rule group was never removed within 240s of delete, "
        f"last observed status={last_status!r}, last error={read_code!r}"
    )
    expected_read = "No object with the provided name or resource identifier was found"
    assert read_message == expected_read, f"expected message {expected_read!r}, got {read_message!r}"

    mutate_code, mutate_message = _error(lambda: nfw.delete_rule_group(RuleGroupArn=rule_group_arn))
    assert mutate_code == "ResourceNotFoundException", \
        f"expected ResourceNotFoundException on a second delete of the same rule group, got {mutate_code}"
    expected_mutate = "No object with the provided name or resource identifier was found"
    assert mutate_message == expected_mutate, f"expected message {expected_mutate!r}, got {mutate_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
