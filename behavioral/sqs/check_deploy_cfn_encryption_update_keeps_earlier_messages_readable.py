"""deploy-cfn-encryption-update-keeps-earlier-messages-readable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-encryption-update-keeps-earlier-messages-readable"
GROUP = "deploy"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation update moving a queue from SSE-SQS to a stack KMS key keeps its URL, reads
    back the key, and keeps messages sent before and after readable; updating back to
    SqsManagedSseEnabled true keeps the KMS-era message and a new one readable.
    """
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    queue_name = ctx.unique_name("sim2real-behav-cfnsse-")

    stack = ctx.unique_name("sim2real-behav-cfnsse-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    cfn.create_stack(StackName=stack, TemplateBody=json.dumps(_template(account, queue_name, "sqs")),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    _wait_stack(cfn, stack, "CREATE_COMPLETE")
    url = _outputs(cfn, stack)["QueueUrl"]
    assert _sse(sqs, url) == {"SqsManagedSseEnabled": "true"}, f"deployed default encryption {_sse(sqs, url)!r}"

    before = "sent-under-sse-sqs-é中\U0001f600"
    sqs.send_message(QueueUrl=url, MessageBody=before)

    cfn.update_stack(StackName=stack, TemplateBody=json.dumps(_template(account, queue_name, "kms")))
    _wait_stack(cfn, stack, "UPDATE_COMPLETE")
    out = _outputs(cfn, stack)
    assert out["QueueUrl"] == url, f"the encryption update replaced the queue: {out['QueueUrl']!r} != {url!r}"
    want = {"SqsManagedSseEnabled": "false", "KmsMasterKeyId": out["KeyArn"], "KmsDataKeyReusePeriodSeconds": "300"}
    got = _poll(lambda: _sse(sqs, url), lambda s: s == want, timeout_s=60.0)
    assert got == want, f"after the SSE-KMS update the queue read {got!r}"

    during = "sent-under-sse-kms-é中\U0001f600"
    sqs.send_message(QueueUrl=url, MessageBody=during)
    bodies = _receive(sqs, url, 2)
    assert sorted(m["Body"] for m in bodies) == sorted([before, during]), (
        f"after the update the queue delivered {sorted(m['Body'] for m in bodies)!r}"
    )
    keep = next(m for m in bodies if m["Body"] == during)
    sqs.delete_message(QueueUrl=url, ReceiptHandle=next(m for m in bodies if m["Body"] == before)["ReceiptHandle"])
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=keep["ReceiptHandle"], VisibilityTimeout=0)

    cfn.update_stack(StackName=stack, TemplateBody=json.dumps(_template(account, queue_name, "sqs-again")))
    _wait_stack(cfn, stack, "UPDATE_COMPLETE")
    got = _poll(lambda: _sse(sqs, url), lambda s: s == {"SqsManagedSseEnabled": "true"}, timeout_s=60.0)
    assert got == {"SqsManagedSseEnabled": "true"}, f"after updating back to SSE-SQS the queue read {got!r}"
    after = "sent-under-sse-sqs-again"
    sqs.send_message(QueueUrl=url, MessageBody=after)
    bodies = _receive(sqs, url, 2)
    assert sorted(m["Body"] for m in bodies) == sorted([during, after]), (
        f"after switching back the queue delivered {sorted(m['Body'] for m in bodies)!r}"
    )
    for m in bodies:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _template(account, queue_name, mode):
    queue_props = {"QueueName": queue_name}
    if mode == "kms":
        queue_props["KmsMasterKeyId"] = {"Fn::GetAtt": ["Key", "Arn"]}
    elif mode == "sqs-again":
        queue_props["SqsManagedSseEnabled"] = True
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "DeletionPolicy": "Delete",
                "UpdateReplacePolicy": "Delete",
                "Properties": {
                    "Description": queue_name,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "account-delegates-to-iam",
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                            "Action": "kms:*",
                            "Resource": "*",
                        }],
                    },
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": queue_props},
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}, "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "Arn"]}}},
    }


def _sse(sqs, url):
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    return {k: attrs[k] for k in ("SqsManagedSseEnabled", "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds") if k in attrs}


def _receive(sqs, url, n, timeout_s=30.0):
    got = {}
    deadline = time.monotonic() + timeout_s
    while len(got) < n and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            got[m["MessageId"]] = m
    assert len(got) == n, f"received {len(got)} of {n} messages: {[m['Body'] for m in got.values()]!r}"
    return list(got.values())


def _poll(probe, predicate, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _outputs(cfn, stack):
    return {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}


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
