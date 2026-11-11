"""deploy-cfn-resource-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-resource-behaves"
GROUP = "deploy"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource deployed by a CloudFormation stack (not CreateResource) is retrievable
    through Cloud Control API's GetResource/ListResources AND actually functions as a real
    SQS queue (send/receive), not merely reaching stack CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-cc-deploy-")
    queue_name = ctx.unique_name("sim2real-cc-deployq-")
    template = json.dumps(
        {
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": queue_name,
                        "VisibilityTimeout": 45,
                        "MessageRetentionPeriod": 345600,
                    },
                }
            },
            "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    queue_url = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "QueueUrl")

    # GetResource through Cloud Control must see the stack-created queue with the
    # properties the template declared.
    props = _get_properties(cc, "AWS::SQS::Queue", queue_url)
    assert props["VisibilityTimeout"] == 45
    assert props["MessageRetentionPeriod"] == 345600

    # ListResources must enumerate it too.
    assert _identifier_in_list(cc, "AWS::SQS::Queue", queue_url)

    # Exercise the real data plane: this must behave like a genuine SQS queue, not a
    # CloudFormation-only stub.
    sqs.send_message(QueueUrl=queue_url, MessageBody="hello-from-cfn-deployed-queue")
    deadline = time.monotonic() + 20
    body = None
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            body = msgs[0]["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            break
    assert body == "hello-from-cfn-deployed-queue"

    # Tear the stack down for real (not merely as best-effort cleanup) and prove the
    # queue -- not just the stack record -- is gone: the physical resource must stop
    # answering its own service API once the stack that owns it is deleted.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    code, message = _error(lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"]))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"queue {queue_url} still answers GetQueueAttributes after its owning stack was "
        f"deleted (code={code!r})"
    )
    expected_message = "The specified queue does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _safe_delete_stack(cfn, stack_name: str) -> None:
    # Best-effort safety net for when `run` raised before reaching its own delete+verify
    # above; the primary teardown assertion lives in the check body, not here.
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _identifier_in_list(cc, type_name: str, identifier: str, max_pages: int = 25) -> bool:
    token = None
    for _ in range(max_pages):
        kwargs = {"TypeName": type_name}
        if token:
            kwargs["NextToken"] = token
        resp = cc.list_resources(**kwargs)
        for desc in resp.get("ResourceDescriptions", []):
            if desc["Identifier"] == identifier:
                return True
        token = resp.get("NextToken")
        if not token:
            break
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
