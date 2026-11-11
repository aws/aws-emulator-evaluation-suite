"""deploy-cloudformation-stack-deletion-removes-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-stack-deletion-removes-resource"
GROUP = "deploy"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A queue created by a CloudFormation stack is readable through GetResource, and once the stack
    is deleted GetResource answers ResourceNotFoundException with the handler's not-found message."""
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")
    stack_name = ctx.unique_name("sim2real-behav-cc-cfndel-")
    template = {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"Tags": [{"Key": "sim2real", "Value": CHECK}]},
            }
        }
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    queue_url = next(r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Queue")

    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert "Arn" in props, "expected the CFN-created queue to be visible as a live CloudControl resource"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _poll_until_not_found(cc, queue_url, timeout_s=90)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetResource after stack deletion, got {code!r}"
    )
    expected = _handler_not_found(message, _queue_not_found_detail(queue_url))
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until_not_found(cc, identifier, *, timeout_s):
    """Bounded retry: CloudControl's data plane can lag CFN's own DELETE_COMPLETE by a beat."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
        except ClientError as e:
            last = (e.response["Error"]["Code"], e.response["Error"].get("Message", ""))
            if last[0] == "ResourceNotFoundException":
                return last
        else:
            last = (None, None)
        time.sleep(3)
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
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
