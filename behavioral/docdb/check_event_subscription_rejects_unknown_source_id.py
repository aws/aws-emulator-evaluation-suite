"""event-subscription-rejects-unknown-source-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-subscription-rejects-unknown-source-id"
GROUP = "rejected"
SERVICES = ["docdb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSubscription rejects a SourceIds entry naming a cluster that does
    not exist, with the exact SourceNotFound fault, and a request naming no source
    ids at all still succeeds against the same topic."""
    sns = ctx.client("sns")
    docdb = ctx.client("docdb")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    bogus_source_id = ctx.unique_name("sim2real-behav-missing-cluster-")
    rejected_name = ctx.unique_name("sim2real-behav-evsub-rejected-")
    code, message = _error(
        lambda: docdb.create_event_subscription(
            SubscriptionName=rejected_name,
            SnsTopicArn=topic_arn,
            SourceType="db-cluster",
            SourceIds=[bogus_source_id],
            Enabled=True,
        )
    )
    assert code == "SourceNotFound", f"expected SourceNotFound, got {code!r}"
    expected = f"Could not find source :{bogus_source_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    existing = docdb.describe_event_subscriptions().get("EventSubscriptionsList", [])
    assert rejected_name not in {s["CustSubscriptionId"] for s in existing}, (
        f"rejected create_event_subscription must not leave {rejected_name!r} behind"
    )

    # positive control: the same topic, no source ids, succeeds.
    sub_name = ctx.unique_name("sim2real-behav-evsub-ok-")
    created = docdb.create_event_subscription(
        SubscriptionName=sub_name,
        SnsTopicArn=topic_arn,
        SourceType="db-cluster",
        Enabled=True,
    )["EventSubscription"]
    ctx.on_cleanup(lambda: _safe_delete_subscription(docdb, sub_name))
    assert created["CustSubscriptionId"] == sub_name, (
        f"expected CustSubscriptionId {sub_name!r}, got {created['CustSubscriptionId']!r}"
    )
    source_ids = created.get("SourceIdsList", [])
    assert source_ids == [], f"expected no source ids, got {source_ids!r}"



def _safe_delete_subscription(docdb, sub_name: str) -> None:
    try:
        docdb.delete_event_subscription(SubscriptionName=sub_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SubscriptionNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
