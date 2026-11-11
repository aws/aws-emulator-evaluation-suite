"""xsvc-iam-2-sns-publish-denied-with-neither-grant."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-sns-publish-denied-with-neither-grant"
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


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A topic-policy grant or an identity-policy grant each lets a user Publish, while a user with
    neither is refused AuthorizationError on the same topic: the two positives are the controls.
    """
    iam = ctx.client("iam")
    sns = ctx.client("sns")

    topic = sns.create_topic(Tags=_RES_TAGS, Name=ctx.unique_name("sim2real-xsvc-sns-nn-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    res_user, res_arn, as_res = _mint_user(ctx, iam, "sim2real-xsvc-sns-rp-")
    id_user, _id_arn, as_id = _mint_user(ctx, iam, "sim2real-xsvc-sns-id-")
    none_user, none_arn, as_none = _mint_user(ctx, iam, "sim2real-xsvc-sns-no-")

    iam.put_user_policy(UserName=id_user, PolicyName="publish-this-topic", PolicyDocument=_policy({
        "Effect": "Allow", "Action": "sns:Publish", "Resource": topic,
    }))
    topic_policy = _policy({
        "Sid": "OnlyTheResourcePolicyUser", "Effect": "Allow", "Principal": {"AWS": res_arn},
        "Action": "sns:Publish", "Resource": topic,
    })
    _settle(lambda: _outcome(lambda: sns.set_topic_attributes(
        TopicArn=topic, AttributeName="Policy", AttributeValue=topic_policy)),
        "OK", description="SetTopicAttributes naming the resource-policy user", streak=1)

    def publish(client):
        return _outcome(lambda: client.publish(TopicArn=topic, Message=f"probe-{uuid.uuid4()}"))

    def refusal(client):
        """(Error.Code, Error.Message) of a refused Publish; a successful Publish fails the check."""
        try:
            client.publish(TopicArn=topic, Message=f"probe-{uuid.uuid4()}")
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("Publish by the user with neither grant succeeded")

    want_refusal = (
        "AuthorizationError",
        f"User: {none_arn} is not authorized to perform: SNS:Publish on resource: {topic} "
        f"because no identity-based policy allows the SNS:Publish action",
    )

    # Positive controls first: both halves of the union work on this exact wiring.
    _settle(lambda: publish(as_res), "OK", description="Publish by the topic-policy-only user")
    _settle(lambda: publish(as_id), "OK", description="Publish by the identity-policy-only user")

    # The negative: neither grant. Settle on the exact code (outlasting InvalidClientTokenId),
    # then hold it while the positives keep succeeding in between.
    _settle(lambda: publish(as_none), "AuthorizationError",
            description="Publish by a user with neither an identity nor a topic-policy grant")
    for i in range(3):
        trio = (publish(as_res), publish(as_id), refusal(as_none))
        assert trio == ("OK", "OK", want_refusal), (
            f"sample {i}: (topic-policy user, identity user, neither) were {trio!r}; expected "
            f"('OK', 'OK', {want_refusal!r})"
        )

    # The refused user really is ungranted on both sides, and nothing was changed to get here.
    assert iam.list_user_policies(UserName=none_user)["PolicyNames"] == [], "neither-user grew a policy"
    assert iam.list_user_policies(UserName=res_user)["PolicyNames"] == [], "topic-policy user grew a policy"
    stored = json.loads(sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"])
    principals = [s.get("Principal") for s in stored["Statement"]]
    assert principals == [{"AWS": res_arn}], (
        f"the topic policy must name only the resource-policy user; principals were {principals!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
