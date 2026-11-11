"""deploy-cfn-kms-encrypted-topic-and-queue-deliver-plaintext."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-kms-encrypted-topic-and-queue-deliver-plaintext"
GROUP = "deploy"
SERVICES = ["sns"]


def _template() -> str:
    tags_ = [{"Key": "sim2real", "Value": CHECK}]
    return json.dumps({
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": f"sim2real-behav-sns {CHECK}",
                    "PendingWindowInDays": 7,
                    "Tags": tags_,
                    "KeyPolicy": {"Version": "2012-10-17", "Statement": [
                        {"Sid": "Account", "Effect": "Allow",
                         "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                         "Action": "kms:*", "Resource": "*"},
                        {"Sid": "SnsDeliversToEncryptedQueue", "Effect": "Allow",
                         "Principal": {"Service": "sns.amazonaws.com"},
                         "Action": ["kms:GenerateDataKey*", "kms:Decrypt"], "Resource": "*"},
                    ]},
                },
            },
            "Topic": {"Type": "AWS::SNS::Topic",
                      "Properties": {"KmsMasterKeyId": {"Ref": "Key"}, "Tags": tags_}},
            "Queue": {"Type": "AWS::SQS::Queue",
                      "Properties": {"KmsMasterKeyId": {"Ref": "Key"}, "Tags": tags_}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}}}]},
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                               "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]}},
            },
        },
        "Outputs": {
            "KeyId": {"Value": {"Ref": "Key"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack's topic and queue both encrypted with one customer managed key report that key, and
    a Publish reaches the encrypted queue with its body and message attributes in plaintext.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    out = _create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sns-cfnkms-"), _template())
    key_arn = kms.describe_key(KeyId=out["KeyId"])["KeyMetadata"]["Arn"]

    topic_key = sns.get_topic_attributes(TopicArn=out["TopicArn"])["Attributes"].get("KmsMasterKeyId")
    queue_key = sqs.get_queue_attributes(QueueUrl=out["QueueUrl"],
                                         AttributeNames=["KmsMasterKeyId"])["Attributes"].get("KmsMasterKeyId")
    resolved = {kms.describe_key(KeyId=k)["KeyMetadata"]["Arn"] if k else None for k in (topic_key, queue_key)}
    assert resolved == {key_arn}, (
        "the topic and the queue must both be encrypted with the stack's key; "
        f"topic set={topic_key is not None}, queue set={queue_key is not None}, same key={resolved == {key_arn}}")

    body = ctx.unique_name("sim2real-encrypted-") + " éß✓"
    mid = sns.publish(TopicArn=out["TopicArn"], Message=body, MessageAttributes={
        "kind": {"DataType": "String", "StringValue": "sim2real-order"}})["MessageId"]
    env = _receive(sqs, out["QueueUrl"], mid, 90)
    assert (env["Message"], env["TopicArn"]) == (body, out["TopicArn"]), (
        f"the encrypted queue must hold the plaintext body from the topic; got Message {env['Message']!r}")
    assert env.get("MessageAttributes", {}).get("kind") == {"Type": "String", "Value": "sim2real-order"}, (
        f"the message attribute must survive the encrypted path; got {env.get('MessageAttributes')!r}")


def _create_stack(ctx, cfn, name: str, body: str) -> dict:
    def _cleanup():
        cfn.delete_stack(StackName=name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _receive(sqs, url: str, message_id: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            env = json.loads(msg["Body"])
            if env.get("MessageId") == message_id:
                return env
    raise AssertionError("the published message never reached the KMS-encrypted queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
