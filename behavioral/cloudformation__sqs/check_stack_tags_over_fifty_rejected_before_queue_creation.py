"""stack-tags-over-fifty-rejected-before-queue-creation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-tags-over-fifty-rejected-before-queue-creation"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(queue_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
        },
    })


def _wait_terminal(cf, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} terminal not met within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id, timeout_s=timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended in {status!r}, expected DELETE_COMPLETE")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """CreateStack with 51 Tags is rejected by CloudFormation's own cap with an exact
    ValidationError, before any resource is created; 50 Tags on the same template deploys and
    all 50 propagate to the queue.
    """
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    ok_name = ctx.unique_name("sim2real-behav-sqscap-ok-")
    ok_queue = ctx.unique_name("sim2real-behav-sqscap-okq-")
    ok_tags = [{"Key": f"sim2real-k{i}", "Value": "v"} for i in range(50)]
    ok_stack_id = cf.create_stack(
        StackName=ok_name, TemplateBody=_template(ok_queue), Tags=ok_tags
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, ok_stack_id))
    status = _wait_terminal(cf, ok_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"positive control: stack {ok_name!r} with 50 Tags ended in {status!r}, expected "
        f"CREATE_COMPLETE"
    )
    queue_url = cf.describe_stack_resource(StackName=ok_stack_id, LogicalResourceId="Queue")[
        "StackResourceDetail"]["PhysicalResourceId"]
    real_url = sqs.get_queue_url(QueueName=ok_queue)["QueueUrl"]
    assert real_url == queue_url, f"SQS's own queue URL {real_url!r} != the stack's Ref {queue_url!r}"
    queue_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    want_tags = {t["Key"]: t["Value"] for t in ok_tags}
    assert queue_tags == want_tags, (
        f"the queue carries {len(queue_tags)} tags; missing {sorted(set(want_tags) - set(queue_tags))!r}, "
        f"extra {sorted(set(queue_tags) - set(want_tags))!r}"
    )

    over_name = ctx.unique_name("sim2real-behav-sqscap-over-")
    over_queue = ctx.unique_name("sim2real-behav-sqscap-overq-")
    over_tags = [{"Key": f"sim2real-k{i}", "Value": "v"} for i in range(51)]

    def _create_over():
        stack_id = cf.create_stack(
            StackName=over_name, TemplateBody=_template(over_queue), Tags=over_tags)["StackId"]
        # Accepted where AWS refuses: undo it before the refusal assert fails.
        ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, stack_id))
        return stack_id

    code, msg = _error(_create_over)
    assert code == "ValidationError", f"51 Tags on CreateStack returned {code!r}, expected ValidationError"
    assert msg == "Tags must have length less than or equal to 50", msg

    unresolved_code, unresolved_msg = _error(lambda: cf.describe_stacks(StackName=over_name))
    assert unresolved_code == "ValidationError", (
        f"CreateStack rejected before any stack existed, so DescribeStacks on {over_name!r} "
        f"should fail too; got {unresolved_code!r}"
    )
    assert unresolved_msg == f"Stack with id {over_name} does not exist", unresolved_msg

    queue_code, queue_msg = _error(lambda: sqs.get_queue_url(QueueName=over_queue))
    assert queue_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"the rejected CreateStack must never have reached SQS, so GetQueueUrl on "
        f"{over_queue!r} should still see no queue; got {queue_code!r}"
    )
    assert queue_msg == "The specified queue does not exist.", queue_msg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
