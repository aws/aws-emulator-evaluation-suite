"""stack-parameter-numeric-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stack-parameter-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A String-typed parameter holding a large integer literal (beyond IEEE-754
    double / 64-bit int precision) is returned by DescribeStacks with no digit
    truncation or float rounding."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-bignum-")

    big_literal = "123456789012345678901234567890123456789"  # far beyond int64/float64 precision
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"BigNumber": {"Type": "String"}},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": "BigNumber", "ParameterValue": big_literal}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=120)

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    params = {p["ParameterKey"]: p["ParameterValue"] for p in stack["Parameters"]}
    assert params["BigNumber"] == big_literal, (
        f"large integer literal mangled: {params['BigNumber']!r} != {big_literal!r}"
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
