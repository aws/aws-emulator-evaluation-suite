"""xsvc-iam-2-sns-topic-policy-only-authorizes-publish."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-sns-topic-policy-only-authorizes-publish"
GROUP = "auth_enforcement"
SERVICES = ["iam", "sns"]

#: Tags that attribute any leftover resource to this check.
_RES_TAGS = [{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


# ===== helpers =====
def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _settle(probe, want, *, description, streak=3, timeout_s=120, interval_s=2):
    """Poll until probe() returns `want` on `streak` CONSECUTIVE calls.

    IAM is eventually consistent and exposes no API that reports a key or a grant as effective,
    so the operation is its own observable. Settling on the EXACT outcome means a not-yet-live
    access key (InvalidClientTokenId) can never be read as the authorization verdict.
    """
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    try:
        iam.delete_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _mint_user(ctx, iam, prefix):
    """A fresh IAM user with NO policy and one access key; returns (name, arn, sns client as it)."""
    name = ctx.unique_name(prefix)
    arn = iam.create_user(UserName=name, Tags=_RES_TAGS)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, name))
    key = iam.create_access_key(UserName=name)["AccessKey"]
    client = ctx.client("sns", creds={
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
        "aws_session_token": None,
    })
    return name, arn, client
# ===== end helpers =====


@tags(
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:happy-path",
)
def run(ctx) -> None:
    """A topic policy naming a same-account user alone authorizes Publish: the policy-less user is
    refused AuthorizationError under the default topic policy and gets a MessageId once
    SetTopicAttributes grants its ARN sns:Publish.
    """
    iam = ctx.client("iam")
    sns = ctx.client("sns")

    topic = sns.create_topic(Tags=_RES_TAGS, Name=ctx.unique_name("sim2real-xsvc-sns-tp-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    user, user_arn, as_user = _mint_user(ctx, iam, "sim2real-xsvc-sns-tp-")

    default = json.loads(sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"])
    assert default.get("Id") == "__default_policy_ID", (
        f"a new topic must carry AWS's default policy before any SetTopicAttributes; got {default!r}"
    )

    def publish():
        return _outcome(lambda: as_user.publish(TopicArn=topic, Message=f"probe-{uuid.uuid4()}"))

    # --- State 1: default topic policy, no identity policy. Settling on the EXACT code also
    # waits out the fresh key's InvalidClientTokenId window.
    _settle(publish, "AuthorizationError",
            description="Publish by a policy-less user against the default topic policy")
    assert iam.list_user_policies(UserName=user)["PolicyNames"] == [], "user must have no inline policy"
    assert iam.list_attached_user_policies(UserName=user)["AttachedPolicies"] == [], (
        "user must have no attached policy"
    )

    # --- State 2: change ONE thing -- a topic policy naming this user.
    topic_policy = _policy({
        "Sid": "TopicPolicyOnly", "Effect": "Allow", "Principal": {"AWS": user_arn},
        "Action": "sns:Publish", "Resource": topic,
    })
    _settle(lambda: _outcome(lambda: sns.set_topic_attributes(
        TopicArn=topic, AttributeName="Policy", AttributeValue=topic_policy)),
        "OK", description="SetTopicAttributes naming the new user", streak=1)
    stored = json.loads(sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"])
    assert [s.get("Sid") for s in stored["Statement"]] == ["TopicPolicyOnly"], (
        f"the stored topic policy must be exactly the one statement installed; got {stored!r}"
    )

    _settle(publish, "OK", description="Publish once the topic policy names the user")
    message = f"payload-{uuid.uuid4()}"
    resp = as_user.publish(TopicArn=topic, Message=message)
    mid = resp.get("MessageId")
    assert isinstance(mid, str) and len(mid) == 36 and mid.count("-") == 4, (
        f"an authorized Publish must return a UUID MessageId; got {resp!r}"
    )

    # The identity side never changed: the grant came from the topic policy alone.
    assert iam.list_user_policies(UserName=user)["PolicyNames"] == [], (
        "user acquired an inline policy; the positive would not isolate the topic policy"
    )
    assert iam.list_attached_user_policies(UserName=user)["AttachedPolicies"] == [], (
        "user acquired an attached policy; the positive would not isolate the topic policy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
