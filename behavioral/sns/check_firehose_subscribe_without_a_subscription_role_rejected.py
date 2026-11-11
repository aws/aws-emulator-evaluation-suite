"""firehose-subscribe-without-a-subscription-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-subscribe-without-a-subscription-role-rejected"
GROUP = "firehose-delivery"
SERVICES = ["sns"]


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _firehose_subs(sns, topic: str) -> list[dict]:
    out = []
    for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic):
        out.extend(s for s in page["Subscriptions"] if s["Protocol"] == "firehose")
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A firehose Subscribe without SubscriptionRoleArn is refused with InvalidParameter and
    leaves no subscription; the same Subscribe with a role ARN is accepted and confirmed at once.
    """
    sns = ctx.client("sns")
    iam = ctx.client("iam")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fhrole-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    stream_arn = (f"arn:aws:firehose:{ctx.region}:{ctx.account}:deliverystream/"
                  f"{ctx.unique_name('sim2real-behav-sns-fhrole-')}")
    role = ctx.unique_name("sim2real-behav-sns-fhrole-")
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}), Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    caller = _subscriber(ctx, topic, role_arn)

    code, message = _error(lambda: sns.subscribe(TopicArn=topic, Protocol="firehose",
                                                 Endpoint=stream_arn, ReturnSubscriptionArn=True))
    assert code == "InvalidParameter", f"a firehose Subscribe without a role gave {code!r}: {message!r}"
    assert message == (
        "Invalid parameter: Delivery protocol firehose can only be subscribed with subscription role arn"), (
        f"the refusal must name the missing SubscriptionRoleArn; got {message!r}")
    assert _firehose_subs(sns, topic) == [], "the refused Subscribe left a firehose subscription behind"

    # Positive control: the same request, carrying the role ARN, from a caller that may pass it.
    deadline = time.monotonic() + 90
    while True:
        try:
            sub = caller.subscribe(TopicArn=topic, Protocol="firehose", Endpoint=stream_arn,
                                   ReturnSubscriptionArn=True,
                                   Attributes={"SubscriptionRoleArn": role_arn})["SubscriptionArn"]
            break
        except ClientError as exc:
            # The subscriber's new identity policy is eventually consistent.
            if exc.response["Error"]["Code"] != "AuthorizationError" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    listed = _firehose_subs(sns, topic)
    assert [(s["SubscriptionArn"], s["Endpoint"]) for s in listed] == [(sub, stream_arn)], (
        f"the accepted firehose subscription must be the topic's only one; listed {len(listed)}")
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert (attrs.get("SubscriptionRoleArn") == role_arn, attrs.get("PendingConfirmation")) == (True, "false"), (
        f"the subscription must keep its role and be confirmed; PendingConfirmation is "
        f"{attrs.get('PendingConfirmation')!r}")


def _subscriber(ctx, topic: str, role_arn: str):
    """An SNS client signed as a role this check creates, which may subscribe to ``topic``
    and pass ``role_arn``."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-sns-fhsub-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "sts:AssumeRole"}]}), Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="subscribe", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sns:Subscribe", "Resource": topic},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="subscribe"))
    deadline = time.monotonic() + 90
    while True:
        try:
            creds = sts.assume_role(RoleArn=arn, RoleSessionName="sim2real-subscriber")["Credentials"]
            break
        except ClientError as exc:
            # A just-created role's trust policy is eventually consistent.
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return ctx.client("sns", creds={"aws_access_key_id": creds["AccessKeyId"],
                                    "aws_secret_access_key": creds["SecretAccessKey"],
                                    "aws_session_token": creds["SessionToken"]})

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
