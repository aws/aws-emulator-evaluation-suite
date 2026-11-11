"""topic-policy-endpoint-condition-limits-which-queue-a-role-may-subscribe."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-policy-endpoint-condition-limits-which-queue-a-role-may-subscribe"
GROUP = "authorization"
SERVICES = ["sns"]

_SID = "RoleMaySubscribeOneEndpoint"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A topic-policy SNS:Subscribe grant conditioned on sns:Endpoint admits only that endpoint:
    another queue is refused with AuthorizationError and creates nothing, and widening the
    condition to name it makes the identical Subscribe succeed."""
    sns = ctx.client("sns")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-epcond-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    # sqs subscriptions auto-confirm without the queue existing, so the endpoints are ARNs
    # minted from names only this run can hold.
    queue_allowed = f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-sns-qa-')}"
    queue_other = f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-sns-qb-')}"

    # The role has no identity policy, so the topic policy is its only source of permission.
    role_name, role_arn = _create_bare_role(ctx, partition)
    original = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])

    def _policy(endpoints: list[str]) -> str:
        doc = dict(original)
        doc["Statement"] = list(original["Statement"]) + [{
            "Sid": _SID,
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": "SNS:Subscribe",
            "Resource": topic_arn,
            "Condition": {"StringEquals": {"sns:Endpoint": endpoints}},
        }]
        return json.dumps(doc)

    _set_policy_until_accepted(sns, topic_arn, _policy([queue_allowed]))

    session = "sim2real-sns-epcond"
    role_sns = _client_as_role(ctx, "sns", role_arn, session)

    # Positive control: the endpoint the condition names is accepted for this role.
    allowed_sub = _subscribe_until_authorized(role_sns, topic_arn, queue_allowed)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=allowed_sub))
    assert allowed_sub.startswith(topic_arn + ":"), (
        f"the role's Subscribe of the named endpoint returned {allowed_sub!r}, not a "
        "subscription ARN under the topic"
    )

    # A different endpoint, same role, same topic, same action.
    code, message = _error(lambda: role_sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_other, ReturnSubscriptionArn=True))
    assumed = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session}"
    expected = (
        f"User: {assumed} is not authorized to perform: SNS:Subscribe on resource: {topic_arn} "
        "because no identity-based policy allows the SNS:Subscribe action"
    )
    assert (code, message) == ("AuthorizationError", expected), (
        "a Subscribe of an endpoint the sns:Endpoint condition does not name must be refused "
        f"with AuthorizationError {expected!r}; got {code!r} {message!r}"
    )
    endpoints = _endpoints(sns, topic_arn)
    assert endpoints == {queue_allowed}, (
        "the refused Subscribe must create nothing: the topic must list only the allowed "
        f"endpoint, but it lists {len(endpoints)} endpoint(s), "
        f"other-queue present={queue_other in endpoints}"
    )

    # Repair: name the second endpoint in the condition as well; the identical call succeeds.
    _set_policy_until_accepted(sns, topic_arn, _policy([queue_allowed, queue_other]))
    other_sub = _subscribe_until_authorized(role_sns, topic_arn, queue_other)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=other_sub))
    endpoints = _endpoints(sns, topic_arn)
    assert endpoints == {queue_allowed, queue_other}, (
        "after the condition names both endpoints the topic must list both; "
        f"it lists {len(endpoints)} endpoint(s), other-queue present={queue_other in endpoints}"
    )


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


def _subscribe_until_authorized(role_sns, topic_arn: str, endpoint: str) -> str:
    """Subscribe as the role, retrying AuthorizationError only while a just-written grant
    propagates; a grant that never takes effect fails loudly."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return role_sns.subscribe(
                TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint,
                ReturnSubscriptionArn=True)["SubscriptionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AuthorizationError" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _endpoints(sns, topic_arn: str) -> set[str]:
    out: set[str] = set()
    for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic_arn):
        out.update(s["Endpoint"] for s in page["Subscriptions"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
