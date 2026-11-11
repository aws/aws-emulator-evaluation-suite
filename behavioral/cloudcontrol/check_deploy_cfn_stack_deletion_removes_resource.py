"""deploy-cfn-stack-deletion-removes-resource."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-stack-deletion-removes-resource"
GROUP = "deploy"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the CloudFormation stack that owns a queue makes Cloud Control's GetResource
    answer ResourceNotFoundException for it, and a further DeleteResource of the gone
    identifier is accepted without bringing the queue back."""
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")

    stack_name = ctx.unique_name("sim2real-cc-del-")
    queue_logical_id = "TargetQueue"
    template = json.dumps(
        {
            "Resources": {
                queue_logical_id: {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"VisibilityTimeout": 30},
                }
            }
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Cleanup is a no-op once the stack is deleted mid-check; make it idempotent.
    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, stack_name))
    status = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack ended in {status}, not CREATE_COMPLETE"

    queue_url = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=queue_logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]

    # While the stack (and queue) is live, GetResource must succeed.
    get_resp = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    assert get_resp["ResourceDescription"]["Identifier"] == queue_url, (
        f"expected GetResource to echo identifier {queue_url!r}, "
        f"got {get_resp['ResourceDescription'].get('Identifier')!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    del_status = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    assert del_status == "DELETE_COMPLETE", f"stack ended in {del_status}, not DELETE_COMPLETE"

    code, message = _poll_until_not_found(cc, queue_url, timeout_s=90)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetResource after stack deletion, got {code!r}"
    )
    expected = _handler_not_found(message, _queue_not_found_detail(queue_url))
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # CloudControl's DeleteResource on an already-gone identifier is idempotent --
    # it is accepted rather than refused with NotFound -- so the invariant worth
    # proving is that this idempotent delete does not resurrect the queue.
    redelete_status = cc.delete_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_url
    )["ProgressEvent"]["OperationStatus"]
    assert redelete_status in ("SUCCESS", "IN_PROGRESS", "PENDING"), (
        f"expected DeleteResource on the already-gone identifier to be accepted as "
        f"an idempotent no-op, got OperationStatus={redelete_status!r}"
    )
    still_gone_code, still_gone_message = _poll_until_not_found(cc, queue_url, timeout_s=90)
    assert still_gone_code == "ResourceNotFoundException", (
        f"idempotent delete-of-absent must not resurrect the queue, but GetResource "
        f"returned {still_gone_code!r} instead of ResourceNotFoundException"
    )
    expected = _handler_not_found(still_gone_message, _queue_not_found_detail(queue_url))
    assert still_gone_message == expected, f"expected message {expected!r}, got {still_gone_message!r}"


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _wait_for_stack_status(cfn: Any, stack_name: str, timeout_s: float = 300.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as err:
            if "does not exist" in str(err):
                return "DELETE_COMPLETE"
            raise
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status, last={status}")


def _delete_stack_if_present(cfn: Any, stack_name: str) -> None:
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
            raise
        return
    if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_name)
    final = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"teardown delete of stack {stack_name} ended {final}")


def _poll_until_not_found(
    cc: Any, identifier: str, timeout_s: float = 90.0
) -> tuple[str | None, str | None]:
    """Poll GetResource until it is refused with ResourceNotFoundException; return the last
    refusal's (Code, Message). A read that still succeeds at the deadline raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last: tuple[str | None, str | None] | None = None
    while time.monotonic() < deadline:
        try:
            cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
        except ClientError as err:
            e = err.response.get("Error", {})
            last = (e.get("Code"), e.get("Message"))
            if last[0] == "ResourceNotFoundException":
                return last
        time.sleep(3)
    if last is None:
        raise AssertionError(f"GetResource for {identifier!r} still succeeds after {timeout_s}s")
    return last


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _queue_not_found_detail(queue_url):
    return (
        "AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{queue_url}' was not found."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
