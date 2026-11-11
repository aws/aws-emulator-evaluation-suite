"""hook-result-not-found-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hook-result-not-found-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHookResult for a random HookResultId fails with HookResultNotFound "The hook result was not
    found.", and ListHookResults with TargetType=STACK for a created stack fails with ValidationError
    "Invalid TargetType: STACK" (STACK is in the model's enum but not a supported filter)."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-hookres-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _best_effort_delete_stack(cfn, stack_name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status}"

    try:
        cfn.list_hook_results(TargetType="STACK", TargetId=stack_id)
    except ClientError as exc:
        list_error = exc.response["Error"]
    else:
        raise AssertionError(
            f"expected ListHookResults(TargetType=STACK) to be rejected, but it "
            f"returned a response for {stack_id}"
        )
    assert list_error["Code"] == "ValidationError", f"unexpected error code: {list_error}"
    assert list_error.get("Message") == "Invalid TargetType: STACK", (
        f"expected message 'Invalid TargetType: STACK', got {list_error}"
    )

    fake_hook_result_id = str(uuid.uuid4())
    error = _client_error(lambda: cfn.get_hook_result(HookResultId=fake_hook_result_id))
    # A well-formed HookResultId that no Hook invocation issued is rejected with the wire
    # code HookResultNotFound (not HookResultNotFoundException), never a 200 with empty data.
    assert error.get("Code") == "HookResultNotFound", f"expected HookResultNotFound, got {error!r}"
    assert error.get("Message") == "The hook result was not found.", (
        f"expected message 'The hook result was not found.', got {error!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


def _best_effort_delete_stack(cfn, stack_name: str) -> None:
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
