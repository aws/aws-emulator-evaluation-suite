"""event-subscription-ops-semantics."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _probe_refusals(cases):
    """{label: callable} -> {label: (code, message)}; raises if any call succeeds."""
    return {label: _refusal(fn) for label, fn in cases.items()}


def _ignore_missing(fn):
    """Cleanup: call *fn*, tolerating only SubscriptionNotFound."""
    try:
        fn()
    except ClientError as exc:
        if _code_of(exc) != "SubscriptionNotFound":
            raise

MSG_NOT_FOUND = "Event Subscription {name} not found"

CHECK = "event-subscription-ops-semantics"
GROUP = 'eventing'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real event subscription's ops succeed (positive control); once it is deleted, the
    identical operations against that now-dead name — and against a name never created at
    all — all report SubscriptionNotFound."""
    rs = ctx.client("redshift")
    sns = ctx.client("sns")

    topic_name = ctx.unique_name("sim2real-behav-rs-subtopic-")
    topic_arn = _retrying(
        lambda: sns.create_topic(
            Name=topic_name, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
        )
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    live = ctx.unique_name("sim2real-behav-rs-sub-live-")
    _retrying(
        lambda: rs.create_event_subscription(
            SubscriptionName=live,
            SnsTopicArn=topic_arn,
            SourceType="cluster",
            Severity="INFO",
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        )
    )
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: rs.delete_event_subscription(SubscriptionName=live))
    )

    # positive control: the subscription exists and Modify's effect is visible on an
    # independent Describe — proves the account and the API are otherwise healthy, so the
    # negative below cannot be "rejects everything".
    found = _retrying(lambda: rs.describe_event_subscriptions(SubscriptionName=live))[
        "EventSubscriptionsList"
    ]
    assert len(found) == 1 and found[0]["Enabled"] is True, (
        f"expected exactly one enabled subscription named {live!r}, got {found}"
    )
    _retrying(lambda: rs.modify_event_subscription(SubscriptionName=live, Enabled=False))
    after_modify = _retrying(lambda: rs.describe_event_subscriptions(SubscriptionName=live))[
        "EventSubscriptionsList"
    ]
    assert after_modify[0]["Enabled"] is False, (
        "ModifyEventSubscription(Enabled=False) did not take effect on an independent read"
    )

    _retrying(lambda: rs.delete_event_subscription(SubscriptionName=live))

    never_created = ctx.unique_name("sim2real-behav-rs-sub-missing-")
    for missing in (live, never_created):
        cases = {
            "DescribeEventSubscriptions": lambda m=missing: rs.describe_event_subscriptions(
                SubscriptionName=m
            ),
            "ModifyEventSubscription": lambda m=missing: rs.modify_event_subscription(
                SubscriptionName=m, Enabled=False
            ),
            "DeleteEventSubscription": lambda m=missing: rs.delete_event_subscription(
                SubscriptionName=m
            ),
        }
        observed = _probe_refusals(cases)
        expected = dict.fromkeys(cases, ("SubscriptionNotFound", MSG_NOT_FOUND.format(name=missing)))
        assert observed == expected, (
            f"event-subscription contract drift for {missing!r} "
            f"({'deleted' if missing == live else 'never created'}):\n"
            f" expected={expected}\n observed={observed}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
