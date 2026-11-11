"""op-contract-signalResource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-signalResource"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SUCCESS SignalResource for a resource with a CreationPolicy drives the stack to CREATE_COMPLETE,
    and SignalResource on a stack name that never existed fails with ValidationError "Stack <name> does
    not exist"."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-signal-")

    template = json.dumps(
        {
            "Resources": {
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "CreationPolicy": {"ResourceSignal": {"Count": 1, "Timeout": "PT5M"}},
                },
            }
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    _wait_for_resource_status(ctx, stack_name, "Wait", {"CREATE_IN_PROGRESS"}, timeout_s=90)

    cfn.signal_resource(
        StackName=stack_name, LogicalResourceId="Wait", UniqueId="sim2real-signal-1", Status="SUCCESS"
    )

    status = _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"}, timeout_s=120
    )
    assert status == "CREATE_COMPLETE", f"signal should have unblocked the wait condition, got {status}"

    missing = ctx.unique_name("sim2real-cfn-missing-")
    code, message = _error(
        lambda: cfn.signal_resource(
            StackName=missing,
            LogicalResourceId="Wait",
            UniqueId="sim2real-signal-x",
            Status="SUCCESS",
        )
    )
    assert code == "ValidationError", f"expected ValidationError for unknown stack, got {code}"
    assert message == f"Stack {missing} does not exist", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises, so a target
    that accepts input AWS refuses fails as an acceptance rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
    )


def _wait_for_resource_status(ctx, stack_name, logical_id, target_statuses, timeout_s=90.0, interval_s=2.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
            last = resp["StackResourceDetail"]["ResourceStatus"]
        except Exception:
            last = None
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"resource {logical_id} in {stack_name} did not reach {target_statuses} (last={last})"
    )


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
