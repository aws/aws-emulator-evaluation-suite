"""e2e-multi-resource-interaction."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-multi-resource-interaction"
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
        except ClientError as e:
            if "does not exist" in str(e):
                return "DELETE_COMPLETE"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """CFN stack with S3 bucket + notification to SQS: upload triggers event delivery."""
    cf = ctx.client("cloudformation")
    bucket_name = ctx.unique_name("sim2real-behav-s3n-")
    queue_name = ctx.unique_name("sim2real-behav-s3nq-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "NotifQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": queue_name},
                },
                "NotifQueuePolicy": {
                    "Type": "AWS::SQS::QueuePolicy",
                    "Properties": {
                        "Queues": [{"Ref": "NotifQueue"}],
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "s3.amazonaws.com"},
                                    "Action": "sqs:SendMessage",
                                    "Resource": {"Fn::GetAtt": ["NotifQueue", "Arn"]},
                                    "Condition": {
                                        "ArnEquals": {
                                            "aws:SourceArn": {
                                                "Fn::Sub": f"arn:aws:s3:::{bucket_name}"
                                            }
                                        }
                                    },
                                }
                            ],
                        },
                    },
                },
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "DependsOn": "NotifQueuePolicy",
                    "Properties": {
                        "BucketName": bucket_name,
                        "NotificationConfiguration": {
                            "QueueConfigurations": [
                                {
                                    "Event": "s3:ObjectCreated:*",
                                    "Queue": {"Fn::GetAtt": ["NotifQueue", "Arn"]},
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "QueueUrl": {"Value": {"Ref": "NotifQueue"}},
                "BucketName": {"Value": {"Ref": "Bucket"}},
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
    deployed_bucket = outputs["BucketName"]

    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    for _ in range(3):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    s3.put_object(Bucket=deployed_bucket, Key="probe.txt", Body=b"cfn-integration-test")

    try:
        received = None
        for _ in range(15):
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
            for msg in resp.get("Messages", []):
                body = json.loads(msg["Body"])
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                if body.get("Event") == "s3:TestEvent":
                    continue
                if "Records" in body:
                    received = body
                    break
            if received:
                break

        assert received is not None, "No S3 event notification received from CFN-deployed resources"
        actual_bucket = received["Records"][0]["s3"]["bucket"]["name"]
        assert actual_bucket == deployed_bucket, (
            f"expected notification for bucket {deployed_bucket!r}, got {actual_bucket!r}"
        )
        actual_key = received["Records"][0]["s3"]["object"]["key"]
        assert actual_key == "probe.txt", f"expected object key 'probe.txt', got {actual_key!r}"
    finally:
        s3.delete_object(Bucket=deployed_bucket, Key="probe.txt")

    cf.delete_stack(StackName=name)
    final_status = _wait_terminal(cf, name)
    assert final_status == "DELETE_COMPLETE", (
        f"stack {name} failed to delete cleanly, ended in {final_status!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
