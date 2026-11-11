"""xsvc-iam-2-sns-topic-policy-deny-beats-identity-allow-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-sns-topic-policy-deny-beats-identity-allow-denied"
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
    """Poll until probe() returns `want` on `streak` consecutive calls (IAM is eventually
    consistent); settling on the exact outcome keeps InvalidClientTokenId from reading as a verdict.
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
    """An explicit Deny in the topic policy beats the caller's identity Allow: the named user's
    Publish flips to AuthorizationError while a control user with the same Allow keeps publishing.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    iam = ctx.client("iam")
    sns = ctx.client("sns")

    topic = sns.create_topic(Tags=_RES_TAGS, Name=ctx.unique_name("sim2real-xsvc-sns-dw-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    allow_doc = _policy({"Effect": "Allow", "Action": "sns:Publish", "Resource": topic})
    deny_user, deny_arn, as_deny = _mint_user(ctx, iam, "sim2real-xsvc-sns-dn-")
    ctl_user, _ctl_arn, as_ctl = _mint_user(ctx, iam, "sim2real-xsvc-sns-ct-")
    for u in (deny_user, ctl_user):
        iam.put_user_policy(UserName=u, PolicyName="publish-this-topic", PolicyDocument=allow_doc)

    def publish(client):
        return _outcome(lambda: client.publish(TopicArn=topic, Message=f"probe-{uuid.uuid4()}"))

    # --- State 1: identity Allow, default topic policy -> both publish.
    _settle(lambda: publish(as_deny), "OK", description="Publish by the to-be-denied user, before the Deny")
    _settle(lambda: publish(as_ctl), "OK", description="Publish by the control user, before the Deny")

    # --- State 2: change ONE thing -- the topic policy becomes a Deny naming only the first user.
    deny_policy = _policy({
        "Sid": "DenyOneUser", "Effect": "Deny", "Principal": {"AWS": deny_arn},
        "Action": "sns:Publish", "Resource": topic,
    })
    sns.set_topic_attributes(TopicArn=topic, AttributeName="Policy", AttributeValue=deny_policy)
    _settle(lambda: publish(as_deny), "AuthorizationError",
            description="Publish by a user whose identity Allow is overridden by a topic Deny")
    for i in range(3):
        pair = (publish(as_deny), publish(as_ctl))
        assert pair == ("AuthorizationError", "OK"), (
            f"sample {i}: (denied user, control user) were {pair!r}; expected "
            f"('AuthorizationError', 'OK') -- the topic Deny must win for its principal only"
        )

    # The identity Allow is still present and identical for both users: Deny won, Allow did not vanish.
    for u in (deny_user, ctl_user):
        doc = iam.get_user_policy(UserName=u, PolicyName="publish-this-topic")["PolicyDocument"]
        stmt = doc["Statement"][0] if isinstance(doc["Statement"], list) else doc["Statement"]
        assert (stmt["Effect"], stmt["Action"], stmt["Resource"]) == ("Allow", "sns:Publish", topic), (
            f"{u}'s identity Allow changed: {doc!r}"
        )
    stored = json.loads(sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"])
    assert [(s["Sid"], s["Effect"]) for s in stored["Statement"]] == [("DenyOneUser", "Deny")], (
        f"topic policy must be exactly the one Deny statement; got {stored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
