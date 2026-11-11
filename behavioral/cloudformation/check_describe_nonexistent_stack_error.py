"""describe-nonexistent-stack-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-stack-error"
GROUP = 'errors'
SERVICES = ['cloudformation']

_TERMINAL_CREATE = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"}
_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStacks on a name that never existed fails with ValidationError "Stack with id <name>
    does not exist", while DescribeStacks on a stack that exists reports it, so a target that
    rejects every DescribeStacks call fails."""
    cf = ctx.client("cloudformation")

    real_name = ctx.unique_name("sim2real-behav-cfn-describe-real-")
    cf.create_stack(
        StackName=real_name,
        TemplateBody=_BUCKET_TEMPLATE,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cf, real_name))
    created = _wait_stack_status(cf, real_name, _TERMINAL_CREATE, timeout_s=180)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"positive control: expected the setup stack to reach CREATE_COMPLETE, "
        f"got {created['StackStatus']}"
    )
    described = cf.describe_stacks(StackName=real_name)["Stacks"][0]
    assert described["StackName"] == real_name, (
        f"positive control: expected DescribeStacks to report {real_name!r}, "
        f"got {described['StackName']!r}"
    )

    missing_name = ctx.unique_name("sim2real-behav-cfn-ghost-")
    error = _expect_error(lambda: cf.describe_stacks(StackName=missing_name))
    err = error.response.get("Error", {})
    code = err.get("Code")
    message = err.get("Message", "")
    assert code == "ValidationError", f"expected ValidationError, got {code!r}: {message}"
    # The code alone is shared with every other DescribeStacks rejection -- the message
    # is what actually proves this is the not-found case.
    expected_message = f"Stack with id {missing_name} does not exist"
    assert message == expected_message, (
        f"expected the stack-not-found message {expected_message!r}, got {message!r}"
    )


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_stack_quiet(cf, name):
    try:
        cf.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(cf, name, terminal_statuses, *, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any status in terminal_statuses."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cf.describe_stacks(StackName=name).get("Stacks", [])
        assert stacks, f"stack {name} not found while waiting for a terminal status"
        last = stacks[0]
        if last.get("StackStatus") in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {name} did not reach a terminal status within {timeout_s}s; last={last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
