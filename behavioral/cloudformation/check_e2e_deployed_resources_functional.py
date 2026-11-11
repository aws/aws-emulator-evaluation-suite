"""e2e-deployed-resources-functional."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-deployed-resources-functional"
GROUP = 'e2e_workflows'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CFN-created resources actually function: deploy SQS queue, send+receive message through it."""
    cf = ctx.client("cloudformation")
    queue_name = ctx.unique_name("sim2real-behav-func-q-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": queue_name},
                }
            },
            "Outputs": {
                "QueueUrl": {"Value": {"Ref": "Queue"}},
                "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            },
        }
    )
    name = _create_and_wait(
        ctx, cf, template, tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    }
    queue_url = outputs["QueueUrl"]
    queue_arn = outputs["QueueArn"]
    assert queue_url, "Stack output QueueUrl is empty"

    sqs = ctx.client("sqs")

    # The Fn::GetAtt-derived Outputs.QueueArn must be a real attribute of the
    # deployed resource, not just an echo of the template's intrinsic function.
    resolved_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    assert resolved_arn == queue_arn, (
        f"Fn::GetAtt QueueArn output {queue_arn!r} does not match the queue's own "
        f"reported ARN {resolved_arn!r}"
    )

    test_body = "cfn-deployed-queue-sim2real-probe"
    sqs.send_message(QueueUrl=queue_url, MessageBody=test_body)
    received = None
    for _ in range(10):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if msgs:
            received = msgs[0]
            break
    assert received is not None, "Could not receive message from CFN-deployed queue"
    assert received["Body"] == test_body, (
        f"Message body mismatch: expected {test_body!r}, got {received['Body']!r}"
    )

    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        assert not resp.get("Messages"), "deleted message reappeared on an independent read"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
