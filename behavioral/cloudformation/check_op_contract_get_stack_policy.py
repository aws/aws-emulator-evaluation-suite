"""op-contract-getStackPolicy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-getStackPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStackPolicy returns an empty body until a policy is set, then
    round-trips the exact policy document written by SetStackPolicy;
    querying an unknown stack is rejected with ValidationError."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-getpolicy-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_BUCKET_TEMPLATE)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    before = cfn.get_stack_policy(StackName=stack_name)
    assert before.get("StackPolicyBody", "") == "", before

    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "Update:Delete", "Principal": "*", "Resource": "*"}
        ]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(policy))

    after = cfn.get_stack_policy(StackName=stack_name)
    body = json.loads(after["StackPolicyBody"])
    assert body["Statement"][0]["Effect"] == "Deny"
    assert body["Statement"][0]["Action"] == "Update:Delete"

    missing = ctx.unique_name("sim2real-cfn-missing-")
    code, message = _error(lambda: cfn.get_stack_policy(StackName=missing))
    assert code == "ValidationError", f"expected ValidationError for unknown stack, got {code}"
    assert message == f"Stack: {missing} does not exist", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
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
