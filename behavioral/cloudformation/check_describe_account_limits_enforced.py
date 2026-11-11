"""describe-account-limits-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-account-limits-enforced"
GROUP = "server-side"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAccountLimits' StackOutputsLimit is actually enforced by CreateStack."""
    cfn = ctx.client("cloudformation")

    limits = {lim["Name"]: lim["Value"] for lim in cfn.describe_account_limits()["AccountLimits"]}
    # Only the limit names are graded; their values are account settings.
    expected_names = {"ConcurrentResourcesLimit", "StackLimit", "StackOutputsLimit"}
    assert set(limits) == expected_names, (
        f"DescribeAccountLimits returned limit names {sorted(limits)!r}, expected {sorted(expected_names)!r}"
    )
    outputs_limit = int(limits["StackOutputsLimit"])
    assert outputs_limit > 0, f"expected a positive StackOutputsLimit, got {outputs_limit}"

    stack_name = ctx.unique_name("sim2real-acctlimit-")
    template = _template_with_outputs(outputs_limit + 1)

    code = None
    message = None
    stack_id = None
    try:
        stack_id = cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )["StackId"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")

    if stack_id is not None:
        ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
        raise AssertionError(
            f"CreateStack accepted a template with {outputs_limit + 1} outputs "
            f"(advertised StackOutputsLimit={outputs_limit}); limit is not enforced"
        )

    expected = (
        "ValidationError",
        f"Template format error: Outputs count {outputs_limit + 1} is greater than max allowed {outputs_limit}",
    )
    assert (code, message) == expected, (
        f"exceeding StackOutputsLimit: expected {expected!r}, got {(code, message)!r}"
    )

    # positive control: one under the limit must succeed, reach CREATE_COMPLETE, and
    # report exactly `outputs_limit` outputs via an independent read (DescribeStacks).
    ok_stack_name = ctx.unique_name("sim2real-acctlimit-ok-")
    ok_template = _template_with_outputs(outputs_limit)
    ok_stack_id = cfn.create_stack(
        StackName=ok_stack_name,
        TemplateBody=json.dumps(ok_template),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ok_stack_id))

    status = _wait_terminal(cfn, ok_stack_name)
    assert status == "CREATE_COMPLETE", f"stack under the limit ended in {status}, expected CREATE_COMPLETE"

    stack = cfn.describe_stacks(StackName=ok_stack_name)["Stacks"][0]
    ok_outputs = stack.get("Outputs", [])
    assert len(ok_outputs) == outputs_limit, (
        f"expected exactly {outputs_limit} outputs (the advertised StackOutputsLimit) "
        f"on the independently-read stack, got {len(ok_outputs)}"
    )


# ===== helpers (self-contained) =====

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _template_with_outputs(count: int) -> dict:
    outputs = {f"Out{i}": {"Value": f"value-{i}"} for i in range(count)}
    return {
        "Resources": {
            "Marker": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
        "Outputs": outputs,
    }


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
