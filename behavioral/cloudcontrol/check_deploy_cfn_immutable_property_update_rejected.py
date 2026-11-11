"""deploy-cfn-immutable-property-update-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-immutable-property-update-rejected"
GROUP = "deploy"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResource rejects patching create-only FifoQueue on a CFN-provisioned queue with
    NotUpdatableException, leaving it unchanged; a mutable-property update still succeeds."""
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-cc-immut-")
    queue_logical_id = "TargetQueue"
    queue_name = ctx.unique_name("sim2real-cc-immut-q-") + ".fifo"
    template = json.dumps(
        {
            "Resources": {
                queue_logical_id: {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": queue_name,
                        "FifoQueue": True,
                        "VisibilityTimeout": 30,
                    },
                }
            }
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    status = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack ended in {status}, not CREATE_COMPLETE"

    queue_url = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=queue_logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]

    # Break exactly one thing: try to flip a create-only property (FifoQueue).
    bad_patch = json.dumps([{"op": "replace", "path": "/FifoQueue", "value": False}])
    code, message = _error(
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=bad_patch
        )
    )
    assert code == "NotUpdatableException", (
        f"expected NotUpdatableException mutating create-only FifoQueue, got {code!r}"
    )
    expected_message = "Invalid patch update: createOnlyProperties [/properties/FifoQueue] cannot be updated"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the live resource is still a FIFO queue, untouched.
    real_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["FifoQueue"]
    )["Attributes"]
    assert real_attrs.get("FifoQueue") == "true", (
        "rejected UpdateResource call still mutated the live FifoQueue attribute: "
        f"{real_attrs.get('FifoQueue')!r}"
    )
    get_resp = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    props = json.loads(get_resp["ResourceDescription"]["Properties"])
    assert props["FifoQueue"] is True, (
        f"GetResource reports FifoQueue={props['FifoQueue']!r} after the rejected update, expected True"
    )

    # Positive control: updating a mutable property still works.
    good_patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 77}])
    update_resp = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=good_patch
    )
    final_event = _poll_request_status(
        cc, update_resp["ProgressEvent"]["RequestToken"], timeout_s=120
    )
    assert final_event["OperationStatus"] == "SUCCESS", final_event
    real_attrs2 = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"]
    )["Attributes"]
    assert real_attrs2["VisibilityTimeout"] == "77", (
        f"the accepted mutable-property update left VisibilityTimeout={real_attrs2['VisibilityTimeout']!r}, expected '77'"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}

_TERMINAL_REQUEST_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _wait_for_stack_status(cfn: Any, stack_name: str, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as err:
            if err.response.get("Error", {}).get("Message") == f"Stack with id {stack_name} does not exist":
                return "DELETE_COMPLETE"
            raise
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status, last={status}")


def _delete_stack_and_wait(cfn: Any, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    status = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    assert status == "DELETE_COMPLETE", (
        f"stack {stack_name} did not tear down cleanly, ended in {status}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _poll_request_status(cc: Any, request_token: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in _TERMINAL_REQUEST_STATUSES:
            return event
        time.sleep(2)
    raise AssertionError(f"request {request_token} never reached a terminal status: {event}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
