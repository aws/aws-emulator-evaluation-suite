"""deploy-cloudformation-resource-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-resource-behaves"
GROUP = "deploy"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-created SQS queue is readable via GetResource, UpdateResource changes the real queue
    (confirmed via SQS), and stack deletion makes GetResource raise ResourceNotFoundException."""
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-behav-cc-cfn-")
    template = {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"VisibilityTimeout": 30},
            }
        }
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    queue_url = next(r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Queue")

    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["VisibilityTimeout"] == 30, props.get("VisibilityTimeout")

    patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 77}])
    upd_resp = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=patch)
    upd_event = _wait_for_progress(ctx, upd_resp["ProgressEvent"]["RequestToken"])
    assert upd_event["OperationStatus"] == "SUCCESS", upd_event

    got2 = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    props2 = json.loads(got2["ResourceDescription"]["Properties"])
    assert props2["VisibilityTimeout"] == 77, "CloudControl UpdateResource did not mutate the CFN-created queue"

    real_attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert real_attrs["VisibilityTimeout"] == "77", (
        "CloudControl reports VisibilityTimeout=77 but the real SQS queue's own attribute is "
        f"{real_attrs['VisibilityTimeout']!r} -- CloudControl's representation has drifted from "
        "the resource it claims to describe"
    )

    cfn.delete_stack(StackName=stack_name)
    del_status = _wait_for_stack_status(cfn, stack_name, timeout_s=300)
    assert del_status == "DELETE_COMPLETE", f"stack ended in {del_status}, not DELETE_COMPLETE"

    code, message = _poll_until_not_found(cc, queue_url, timeout_s=90)
    assert code == "ResourceNotFoundException", (
        f"expected stack deletion to propagate through CloudControl as ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected = _handler_not_found(message, _queue_not_found_detail(queue_url))
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _wait_for_stack_status(cfn, stack_name, timeout_s=300.0):
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


def _delete_stack_if_present(cfn, stack_name):
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


def _poll_until_not_found(cc, identifier, timeout_s=90.0):
    """Poll GetResource until it is refused; return the refusal code and message. A queue that stays
    readable past the deadline raises, so a target that never removes it fails loudly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException" or time.monotonic() > deadline:
                return code, err.response["Error"].get("Message", "")
        else:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"GetResource still reads {identifier!r} {timeout_s}s after the stack deletion"
                )
        time.sleep(3)


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
