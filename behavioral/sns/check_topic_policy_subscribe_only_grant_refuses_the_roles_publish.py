"""topic-policy-subscribe-only-grant-refuses-the-roles-publish."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-policy-subscribe-only-grant-refuses-the-roles-publish"
GROUP = "authorization"
SERVICES = ["sns"]

_SID = "RoleGrant"


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
    """A role granted only SNS:Subscribe by the topic policy can subscribe, but its Publish is
    refused with AuthorizationError and never delivered; adding SNS:Publish to that statement
    makes its next Publish deliver."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-subonly-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url, queue_arn = _create_queue(ctx, topic_arn)
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    role_name, role_arn = _create_bare_role(ctx, partition)
    original = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])

    def _policy(actions: list[str]) -> str:
        doc = dict(original)
        doc["Statement"] = list(original["Statement"]) + [{
            "Sid": _SID, "Effect": "Allow", "Principal": {"AWS": role_arn},
            "Action": actions, "Resource": topic_arn,
        }]
        return json.dumps(doc)

    _set_policy_until_accepted(sns, topic_arn, _policy(["SNS:Subscribe"]))
    session = "sim2real-sns-subonly"
    role_sns = _client_as_role(ctx, "sns", role_arn, session)

    # Positive control: the granted action works for this role.
    endpoint = f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-sns-q-')}"
    role_sub = _until_authorized(lambda: role_sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint,
        ReturnSubscriptionArn=True)["SubscriptionArn"])
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=role_sub))

    denied_body = ctx.unique_name("sim2real-denied-")
    code, message = _error(lambda: role_sns.publish(TopicArn=topic_arn, Message=denied_body))
    assumed = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session}"
    expected = (
        f"User: {assumed} is not authorized to perform: SNS:Publish on resource: {topic_arn} "
        "because no identity-based policy allows the SNS:Publish action"
    )
    assert (code, message) == ("AuthorizationError", expected), (
        "a role granted only SNS:Subscribe must be refused Publish with AuthorizationError "
        f"{expected!r}; got {code!r} {message!r}"
    )

    # The owner's later publish arriving shows the refused one had time to arrive and did not.
    control_body = ctx.unique_name("sim2real-owner-")
    sns.publish(TopicArn=topic_arn, Message=control_body)
    got = _drain_until(sqs, queue_url, {control_body}, 60)
    assert control_body in got, f"the owner's control publish never reached the subscriber; got {got!r}"
    assert denied_body not in got, "the refused Publish was delivered to the subscriber anyway"

    _set_policy_until_accepted(sns, topic_arn, _policy(["SNS:Subscribe", "SNS:Publish"]))
    granted_body = ctx.unique_name("sim2real-granted-")
    mid = _until_authorized(lambda: role_sns.publish(TopicArn=topic_arn, Message=granted_body)["MessageId"])
    assert mid, "the role's Publish, once granted, must return a MessageId"
    got = _drain_until(sqs, queue_url, {granted_body}, 60)
    assert granted_body in got, f"the role's granted Publish never reached the subscriber; got {got!r}"
    assert denied_body not in got, "the earlier refused Publish surfaced at the subscriber later"


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


def _create_bare_role(ctx, partition: str) -> tuple[str, str]:
    """A role the account root may assume, with no identity policy of its own."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sns-r-")
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


def _set_policy_until_accepted(sns, topic_arn: str, policy: str) -> None:
    """SetTopicAttributes(Policy); a just-created role can be rejected as a Principal with
    InvalidParameter until IAM propagates it, so that one code is retried, bounded."""
    deadline = time.monotonic() + 90
    while True:
        try:
            sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameter" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    stored = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    sids = sorted(st.get("Sid", "") for st in stored["Statement"])
    want = sorted(st.get("Sid", "") for st in json.loads(policy)["Statement"])
    assert sids == want, f"the stored topic policy carries statements {sids!r}, expected {want!r}"


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
