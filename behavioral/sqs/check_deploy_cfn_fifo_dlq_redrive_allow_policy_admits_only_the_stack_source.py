"""deploy-cfn-fifo-dlq-redrive-allow-policy-admits-only-the-stack-source."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-fifo-dlq-redrive-allow-policy-admits-only-the-stack-source"
GROUP = "deploy"
SERVICES = ["sqs"]

MAX_RECEIVE_COUNT = 1


# timing:real-time — visibility: 1 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stack FIFO DLQ whose RedriveAllowPolicy admits only the stack source receives a failing
    message after maxReceiveCount with body and MessageGroupId intact, the group's next message is
    delivered, and a FIFO queue outside the stack is refused that DLQ and keeps no RedrivePolicy.
    """
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")
    names = {
        "Source": ctx.unique_name("sim2real-behav-cfnfifo-") + ".fifo",
        "Dlq": ctx.unique_name("sim2real-behav-cfnfifo-dlq-") + ".fifo",
    }

    stack = ctx.unique_name("sim2real-behav-cfnfifo-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    cfn.create_stack(StackName=stack, TemplateBody=json.dumps(_template(names)),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    _wait_stack(cfn, stack, "CREATE_COMPLETE")
    out = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    src_url, dlq_url, dlq_arn = out["SourceUrl"], out["DlqUrl"], out["DlqArn"]

    allow = json.loads(sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["RedriveAllowPolicy"])["Attributes"]["RedriveAllowPolicy"])
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert allow == {"redrivePermission": "byQueue", "sourceQueueArns": [src_arn]}, f"deployed RedriveAllowPolicy {allow!r}"

    group = "orders-1"
    for i, body in enumerate(["poison", "next-in-group"]):
        sqs.send_message(QueueUrl=src_url, MessageBody=body, MessageGroupId=group, MessageDeduplicationId=f"d{i}")

    first = _receive(sqs, src_url, visibility=1)
    assert first["Body"] == "poison", f"the group's head was {first['Body']!r}, expected 'poison'"
    # The consumer fails on it: no delete. Once maxReceiveCount is spent it moves to the DLQ and the
    # group's next message becomes deliverable.
    poison_deliveries = 1
    dead = nxt = None
    deadline = time.monotonic() + 90.0
    while (dead is None or nxt is None) and time.monotonic() < deadline:
        if dead is None:
            msgs = sqs.receive_message(
                QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=1, AttributeNames=["MessageGroupId"]
            ).get("Messages", [])
            dead = msgs[0] if msgs else None
        if nxt is None:
            for m in sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=1, VisibilityTimeout=30).get("Messages", []):
                if m["Body"] == "poison":
                    poison_deliveries += 1
                else:
                    nxt = m
    assert dead is not None, "the failing message never reached the stack's DLQ"
    assert poison_deliveries == MAX_RECEIVE_COUNT, (
        f"the failing message was delivered {poison_deliveries} times from the source; maxReceiveCount is {MAX_RECEIVE_COUNT}"
    )
    assert dead["Body"] == "poison", f"the DLQ held {dead['Body']!r}"
    assert dead["Attributes"]["MessageGroupId"] == group, f"the DLQ copy's group was {dead['Attributes']!r}"
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=dead["ReceiptHandle"])
    assert nxt is not None, "the group's next message was never delivered after its head was dead-lettered"
    assert nxt["Body"] == "next-in-group", f"after the move the group delivered {nxt['Body']!r}"
    sqs.delete_message(QueueUrl=src_url, ReceiptHandle=nxt["ReceiptHandle"])

    outsider = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-cfnfifo-out-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=outsider))
    err = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=outsider,
        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": MAX_RECEIVE_COUNT})},
    ))
    assert err["Code"] == "InvalidParameterValue", f"an unlisted source naming the stack DLQ gave {err!r}"
    assert err["Message"] == (
        f"Value RedrivePolicy(maxReceiveCount={MAX_RECEIVE_COUNT}, deadLetterTargetArn={dlq_arn}) for parameter "
        f"RedrivePolicy is invalid. Reason: The value for the dead-letter queue's RedriveAllowPolicy "
        f"attribute prevents you from completing this request."
    ), f"got {err['Message']!r}"
    attrs = sqs.get_queue_attributes(QueueUrl=outsider, AttributeNames=["All"])["Attributes"]
    assert "RedrivePolicy" not in attrs, f"the refused update stored {attrs.get('RedrivePolicy')!r}"


def _template(names):
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Dlq": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": names["Dlq"],
                    "FifoQueue": True,
                    "RedriveAllowPolicy": {
                        "redrivePermission": "byQueue",
                        "sourceQueueArns": [
                            {"Fn::Sub": "arn:${AWS::Partition}:sqs:${AWS::Region}:${AWS::AccountId}:" + names["Source"]}
                        ],
                    },
                },
            },
            "Source": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": names["Source"],
                    "FifoQueue": True,
                    "VisibilityTimeout": 1,
                    "RedrivePolicy": {"deadLetterTargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]}, "maxReceiveCount": MAX_RECEIVE_COUNT},
                },
            },
        },
        "Outputs": {
            "SourceUrl": {"Value": {"Ref": "Source"}},
            "DlqUrl": {"Value": {"Ref": "Dlq"}},
            "DlqArn": {"Value": {"Fn::GetAtt": ["Dlq", "Arn"]}},
        },
    }


def _receive(sqs, url, *, visibility, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=visibility).get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError(f"no message arrived on the queue within {timeout_s}s")


def _error(fn):
    """The Error dict ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_stack(cfn, stack, want, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == want:
            return
        if not status.endswith("_IN_PROGRESS") or time.monotonic() > deadline:
            events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
            reasons = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
                       for e in events if e["ResourceStatus"].endswith("_FAILED")]
            raise AssertionError(f"stack reached {status!r}, expected {want!r}; failed events {reasons!r}")
        time.sleep(5)


def _delete_stack(cfn, stack):
    """Delete the stack and wait; a stack that never got created is already gone."""
    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as exc:
        if "does not exist" in exc.response["Error"]["Message"]:
            return
        raise
    cfn.delete_stack(StackName=stack)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
