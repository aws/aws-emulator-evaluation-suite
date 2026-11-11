"""stack-tag-value-unicode-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stack-tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation stores a stack tag value with each non-ASCII code point replaced by '?';
    DescribeStacks returns that coerced value on repeat reads and ListStacks lists the stack."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-tagunicode-")

    # AWS resource tags only allow letters (any script), numbers, spaces, and
    # the punctuation set _ . : / = + - @ (real AWS rejects '&', '<', '>',
    # '"', '%' outright with ValidationError) -- so this stays within the
    # allowed set while still covering multi-script unicode fidelity.
    tag_value = "日本語タグ Björk café_100:build/v1.0+release-2024@sim2real"
    expected_tag_value = tag_value.encode("ascii", errors="replace").decode("ascii")
    # The value must contain non-ASCII code points, or the coercion assertion is vacuous.
    assert expected_tag_value != tag_value, (
        "test data has no non-ASCII code points, so ASCII-coercion would pass vacuously: "
        + json.dumps(tag_value, ensure_ascii=True)
    )
    assert any(ord(c) > 127 for c in tag_value), (
        "tag_value has no code point above U+007F: " + json.dumps(tag_value, ensure_ascii=True)
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "Owner", "Value": tag_value}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=120)

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    tags = {t["Key"]: t["Value"] for t in stack["Tags"]}
    assert tags["Owner"] == expected_tag_value, (
        "tag value did not match real AWS's ASCII-coercion contract: "
        + json.dumps(tags["Owner"], ensure_ascii=True)
        + " != "
        + json.dumps(expected_tag_value, ensure_ascii=True)
    )

    # Confirm the stack is discoverable via ListStacks under the same name
    # (independent of tag content, since StackSummary does not expose Tags).
    found = False
    paginator = cfn.get_paginator("list_stacks")
    for page in paginator.paginate(
        StackStatusFilter=[
            "CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
        ]
    ):
        for summary in page["StackSummaries"]:
            if summary["StackName"] == stack_name:
                found = True
                break
        if found:
            break
    assert found, f"stack {stack_name} not found via ListStacks"

    # A second read confirms the coerced value is persisted, not just echoed on creation.
    stack_again = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    tags_again = {t["Key"]: t["Value"] for t in stack_again["Tags"]}
    assert tags_again["Owner"] == expected_tag_value, (
        "coerced tag value did not persist stably across a second DescribeStacks read: "
        + json.dumps(tags_again["Owner"], ensure_ascii=True)
        + " != "
        + json.dumps(expected_tag_value, ensure_ascii=True)
    )


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {terminal_statuses}, last status {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
