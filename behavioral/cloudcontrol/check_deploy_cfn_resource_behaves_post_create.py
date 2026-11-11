"""deploy-cfn-resource-behaves-post-create."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-cfn-resource-behaves-post-create"
GROUP = "deploy"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a CFN stack reaches CREATE_COMPLETE, CloudControl GetResource reflects live
    properties of the underlying resource, and UpdateResource actually mutates the real
    resource (verified independently through the resource's own service API)."""
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-cc-deploy-")
    queue_logical_id = "TargetQueue"
    template = json.dumps(
        {
            "Resources": {
                queue_logical_id: {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "VisibilityTimeout": 30,
                        "MessageRetentionPeriod": 345600,
                    },
                }
            }
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    status = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack ended in {status}, not CREATE_COMPLETE"

    queue_url = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=queue_logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]

    # GetResource via CloudControl must reflect live properties of the real resource.
    get_resp = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    props = json.loads(get_resp["ResourceDescription"]["Properties"])
    assert get_resp["ResourceDescription"]["Identifier"] == queue_url, (
        f"GetResource identifier {get_resp['ResourceDescription']['Identifier']!r} != "
        f"stack-created queue url {queue_url!r}"
    )
    assert int(props["VisibilityTimeout"]) == 30, (
        f"expected VisibilityTimeout 30 from GetResource, got {props.get('VisibilityTimeout')!r}"
    )
    assert int(props["MessageRetentionPeriod"]) == 345600, (
        "expected MessageRetentionPeriod 345600 from GetResource, got "
        f"{props.get('MessageRetentionPeriod')!r}"
    )

    # UpdateResource must actually change the live resource, not just CloudControl's view.
    patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 90}])
    update_resp = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=patch
    )
    request_token = update_resp["ProgressEvent"]["RequestToken"]
    final_event = _poll_request_status(cc, request_token, timeout_s=120)
    assert final_event["OperationStatus"] == "SUCCESS", final_event

    real_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"]
    )["Attributes"]
    assert real_attrs["VisibilityTimeout"] == "90", (
        "UpdateResource reported SUCCESS but the real SQS queue's VisibilityTimeout "
        f"is {real_attrs['VisibilityTimeout']!r}, not 90"
    )

    # GetResource must now reflect the updated live state too.
    get_resp2 = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    props2 = json.loads(get_resp2["ResourceDescription"]["Properties"])
    assert int(props2["VisibilityTimeout"]) == 90, (
        "GetResource still shows a stale VisibilityTimeout after UpdateResource reported "
        f"SUCCESS and the real queue confirmed 90: got {props2.get('VisibilityTimeout')!r}"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}

_TERMINAL_REQUEST_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _wait_for_stack_status(cfn: Any, stack_name: str, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status, last={status}")


def _delete_stack_and_wait(cfn: Any, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_status(cfn, stack_name, timeout_s=300)


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
