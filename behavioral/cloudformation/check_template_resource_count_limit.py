"""template-resource-count-limit."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-resource-count-limit"
GROUP = "template-limits"
SERVICES = ["cloudformation"]

_LIMIT = 500
_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]


def _template(count: int) -> str:
    resources = {f"H{i:03d}": {"Type": "AWS::CloudFormation::WaitConditionHandle"} for i in range(count)}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources},
                      separators=(",", ":"))


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack for a stack a refused create should never have made; waits to DELETE_COMPLETE."""
    cf.delete_stack(StackName=stack_id)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A template of 500 resources validates, and GetTemplateSummary's ResourceTypes lists one entry
    per resource rather than deduplicating by type; 501 resources is a Template format error from
    ValidateTemplate and from CreateStack, which makes no stack.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html
    """
    cf = ctx.client("cloudformation")

    at_limit = _template(_LIMIT)
    cf.validate_template(TemplateBody=at_limit)
    summary = cf.get_template_summary(TemplateBody=at_limit)
    expected_types = ["AWS::CloudFormation::WaitConditionHandle"] * _LIMIT
    assert summary["ResourceTypes"] == expected_types, (
        f"GetTemplateSummary ResourceTypes: one entry per resource, not deduplicated; "
        f"got {len(summary['ResourceTypes'])} entries"
    )

    over = _template(_LIMIT + 1)
    expected = (
        "ValidationError",
        f"Template format error: Number of resources, {_LIMIT + 1}, is greater than maximum allowed, {_LIMIT}",
    )
    got = _error(lambda: cf.validate_template(TemplateBody=over))
    assert got == expected, f"ValidateTemplate with {_LIMIT + 1} resources: got {got!r}"

    name = ctx.unique_name("sim2real-behav-tplres-")
    try:
        stack_id = cf.create_stack(StackName=name, TemplateBody=over, Tags=_TAGS)["StackId"]
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    else:
        ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
        raise AssertionError(f"CreateStack with {_LIMIT + 1} resources was accepted as {stack_id}")
    assert got == expected, f"CreateStack with {_LIMIT + 1} resources: got {got!r}"
    gone = _error(lambda: cf.describe_stacks(StackName=name))
    assert gone == ("ValidationError", f"Stack with id {name} does not exist"), (
        f"a refused create must leave no stack; DescribeStacks gave {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
