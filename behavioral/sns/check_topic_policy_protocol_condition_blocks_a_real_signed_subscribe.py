"""topic-policy-protocol-condition-blocks-a-real-signed-subscribe."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "topic-policy-protocol-condition-blocks-a-real-signed-subscribe"
GROUP = "permissions"
SERVICES = ["sns"]

_SCENARIO = "sns-topic-policy-condition"

_DENY_SID = "sim2realDenyEmailProtocol"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A topic-policy Deny on SNS:Subscribe conditioned on sns:protocol == "email" refuses an email
    Subscribe with AuthorizationError and creates no subscription, while an sqs Subscribe still
    succeeds; restoring the original policy lets the identical email Subscribe succeed.

    Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonsns.html
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)

    original_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get("Policy")
    assert original_policy, (
        "a freshly created topic must expose a default Policy document through "
        f"GetTopicAttributes; got {original_policy!r} — the restore leg needs it verbatim"
    )
    original_doc = json.loads(original_policy)
    assert original_doc.get("Statement"), (
        f"the default topic policy must carry at least one statement, got {original_doc!r}"
    )

    email_before = f"sim2real-behav-sns-allowed-{uuid.uuid4().hex[:10]}@example.com"
    email_denied = f"sim2real-behav-sns-denied-{uuid.uuid4().hex[:10]}@example.com"

    # ---- beat 1: the positive control, before anything is changed -------------------------
    sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email_before)
    # A pending email subscription has no resolvable SubscriptionArn, so it cannot be
    # unsubscribed individually; DeleteTopic (already registered) removes it.
    listed = _endpoints(ctx, topic_arn)
    assert listed.get(email_before) == "email", (
        "control: an email Subscribe must succeed and appear in ListSubscriptionsByTopic under "
        f"the default topic policy; endpoints listed were {sorted(listed)}"
    )

    # ---- beat 2: break exactly one thing — add the condition-scoped Deny ------------------
    denied_doc = dict(original_doc)
    denied_doc["Statement"] = list(original_doc["Statement"]) + [{
        "Sid": _DENY_SID,
        "Effect": "Deny",
        "Principal": {"AWS": "*"},
        "Action": "SNS:Subscribe",
        "Resource": topic_arn,
        "Condition": {"StringEquals": {"sns:protocol": "email"}},
    }]
    _set_policy(ctx, topic_arn, json.dumps(denied_doc), expect_sid_present=True)

    # ---- beat 3: the specific refusal on the identical call -------------------------------
    code, message = _error(lambda: sns.subscribe(
        TopicArn=topic_arn, Protocol="email", Endpoint=email_denied))
    assert code == "AuthorizationError", (
        "expected an email Subscribe to be refused with Code 'AuthorizationError' while the "
        "topic policy denies SNS:Subscribe under StringEquals sns:protocol=email; got Code "
        f"{code!r} and Message {message!r}"
    )
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected_auth_message = (
        f"User: {caller_arn} is not authorized to perform: SNS:Subscribe on resource: "
        f"{topic_arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected_auth_message, (
        f"unexpected AuthorizationError message for the denied email Subscribe: {message!r}"
    )

    # ---- beat 4: the condition is scoped — an sqs Subscribe still succeeds ----------------
    # SNS auto-confirms an sqs-protocol subscription without verifying the queue exists, so this
    # control needs no SQS resource and keeps the check single-service.
    parts = topic_arn.split(":")
    queue_arn = f"arn:aws:sqs:{parts[3]}:{parts[4]}:{ctx.unique_name('sim2real-behav-sns-q-')}"
    sqs_sub = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sqs_sub: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    assert sqs_sub and sqs_sub != "pending confirmation", (
        "positive control: an sqs Subscribe must still succeed while the Deny is scoped to "
        f"sns:protocol=email — without this leg, 'denies email' cannot be told apart from "
        f"'denies every Subscribe'; got SubscriptionArn {sqs_sub!r}"
    )
    after_control = _endpoints(ctx, topic_arn)
    assert after_control.get(queue_arn) == "sqs", (
        "positive control: the sqs subscription must be visible in ListSubscriptionsByTopic; "
        f"endpoints listed were {sorted(after_control)}"
    )

    # ---- beat 5: effect absent, read through a different operation ------------------------
    assert email_denied not in after_control, (
        "a Subscribe refused with AuthorizationError must create no subscription: "
        f"{email_denied!r} is present in ListSubscriptionsByTopic anyway (protocol "
        f"{after_control.get(email_denied)!r})"
    )

    # ---- beat 6: restore the original document verbatim, and the identical call succeeds ---
    _set_policy(ctx, topic_arn, original_policy, expect_sid_present=False)
    sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email_denied)
    restored = _endpoints(ctx, topic_arn)
    assert restored.get(email_denied) == "email", (
        "restore: with the Deny statement removed, the identical email Subscribe must succeed "
        f"and be listed; endpoints listed were {sorted(restored)}"
    )




def _endpoints(ctx, topic_arn: str) -> dict[str, str]:
    """{Endpoint: Protocol} for every subscription on the topic, following NextToken. Both fields
    are hard-subscripted so a record missing either one fails loudly."""
    sns = ctx.client("sns")
    out: dict[str, str] = {}
    token: str | None = None
    while True:
        kwargs = {"TopicArn": topic_arn}
        if token:
            kwargs["NextToken"] = token
        page = sns.list_subscriptions_by_topic(**kwargs)
        for sub in page["Subscriptions"]:
            out[sub["Endpoint"]] = sub["Protocol"]
        token = page.get("NextToken")
        if not token:
            return out


def _set_policy(ctx, topic_arn: str, policy: str, *, expect_sid_present: bool) -> None:
    """Install a topic Policy and poll an independent read until it reflects the change."""
    sns = ctx.client("sns")
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy)
    _poll_until(
        lambda: sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get("Policy", ""),
        lambda stored: (_DENY_SID in stored) is expect_sid_present,
        timeout_s=60.0,
        interval_s=2.0,
        description=(
            f"GetTopicAttributes reports the {_DENY_SID} statement "
            f"{'present' if expect_sid_present else 'absent'}"
        ),
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(
        Name=name, Attributes=dict(attributes or {}), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}"
            )
        time.sleep(interval_s)
        value = fn()
    return value


def _error(fn) -> tuple[str | None, str]:
    """(Code, Message) for a refused call. RAISES on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        "expected this call to be refused, but it succeeded; an over-permissive target must "
        "not be able to report a missing error code instead of an unexpected success"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
