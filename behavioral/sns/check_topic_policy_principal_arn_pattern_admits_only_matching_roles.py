"""topic-policy-principal-arn-pattern-admits-only-matching-roles."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-policy-principal-arn-pattern-admits-only-matching-roles"
GROUP = "authorization"
SERVICES = ["sns"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic policy granting SNS:Publish to Principal * under an ArnLike aws:PrincipalArn pattern
    admits only matching roles: a matching role's messages are delivered, while a non-matching
    role is refused with AuthorizationError and nothing it sent arrives."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-pattern-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url, queue_arn = _create_queue(ctx, topic_arn)
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    # Neither role has an identity policy; only the topic policy can admit them.
    family = ctx.unique_name("sim2real-behav-sns-")
    inside_name, inside_arn = _create_bare_role(ctx, partition, f"{family}-pub-a")
    outside_name, outside_arn = _create_bare_role(ctx, partition, f"{family}-ops-a")
    original = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    doc = dict(original)
    doc["Statement"] = list(original["Statement"]) + [{
        "Sid": "PublisherRolesByPattern", "Effect": "Allow", "Principal": {"AWS": "*"},
        "Action": "SNS:Publish", "Resource": topic_arn,
        "Condition": {"ArnLike": {"aws:PrincipalArn": f"arn:{partition}:iam::{ctx.account}:role/{family}-pub-*"}},
    }]
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(doc))

    inside = _client_as_role(ctx, "sns", inside_arn, "sim2real-sns-in")
    outside = _client_as_role(ctx, "sns", outside_arn, "sim2real-sns-out")

    granted = ctx.unique_name("sim2real-inside-")
    _until_authorized(lambda: inside.publish(TopicArn=topic_arn, Message=granted))
    denied = ctx.unique_name("sim2real-outside-")
    code, message = _error(lambda: outside.publish(TopicArn=topic_arn, Message=denied))
    assumed = f"arn:{partition}:sts::{ctx.account}:assumed-role/{outside_name}/sim2real-sns-out"
    expected = (
        f"User: {assumed} is not authorized to perform: SNS:Publish on resource: {topic_arn} "
        "because no identity-based policy allows the SNS:Publish action"
    )
    assert (code, message) == ("AuthorizationError", expected), (
        "a role outside the aws:PrincipalArn pattern must be refused with AuthorizationError "
        f"{expected!r}; got {code!r} {message!r}"
    )
    again = ctx.unique_name("sim2real-inside-again-")
    inside.publish(TopicArn=topic_arn, Message=again)
    got = _drain_until(sqs, queue_url, {granted, again}, 60)
    assert {granted, again} <= set(got), f"the matching role's messages must be delivered; got {got!r}"
    assert denied not in got, "the refused Publish from the non-matching role was delivered anyway"


def _create_queue(ctx, topic_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-subq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    return url, arn


def _create_bare_role(ctx, partition: str, name: str) -> tuple[str, str]:
    """A role named ``name`` the account root may assume, with no identity policy of its own."""
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _client_as_role(ctx, service: str, role_arn: str, session: str):
    """A client signed by an assumed session of ``role_arn``; retries only while IAM has not
    yet propagated the new role's trust policy."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 90
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _until_authorized(fn):
    """Run ``fn``, retrying AuthorizationError only while a just-written grant propagates."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AuthorizationError" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _drain_until(sqs, url: str, wanted: set[str], timeout_s: float) -> list[str]:
    out: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(out):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"])["Message"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
