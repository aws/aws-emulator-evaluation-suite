"""tag-resource-scopes-tags-per-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-scopes-tags-per-resource"
GROUP = 'tagging'
SERVICES = ['ce']

_THRESHOLD_EXPR = {
    "Dimensions": {
        "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
        "Values": ["100"],
        "MatchOptions": ["GREATER_THAN_OR_EQUAL"],
    }
}


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource scope tags per resource
    ARN: tagging an anomaly monitor and an anomaly subscription with disjoint
    keys leaves each resource's own tag set untouched by the other's edits.
    """
    ce = ctx.client("ce")
    sns = ctx.client("sns")

    monitor_name = ctx.unique_name("sim2real-behav-ce-mon-")
    monitor_arn = ce.create_anomaly_monitor(
        AnomalyMonitor={
            "MonitorName": monitor_name,
            "MonitorType": "DIMENSIONAL",
            "MonitorDimension": "SERVICE",
        },
        ResourceTags=[{"Key": "sim2real", "Value": "tag-resource-scopes-tags-per-resource"},
                      {"Key": "owner", "Value": "monitor"}],
    )["MonitorArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_monitor(MonitorArn=monitor_arn), "UnknownMonitorException"
    ))

    topic_name = ctx.unique_name("sim2real-behav-ce-topic-")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic_arn), "NotFound"))
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=(
            '{"Version":"2012-10-17","Statement":[{"Sid":"sim2real-behav-ce-costalerts",'
            '"Effect":"Allow","Principal":{"Service":"costalerts.amazonaws.com"},'
            f'"Action":"SNS:Publish","Resource":"{topic_arn}"}}]}}'
        ),
    )

    sub_name = ctx.unique_name("sim2real-behav-ce-sub-")
    sub_arn = ce.create_anomaly_subscription(
        AnomalySubscription={
            "SubscriptionName": sub_name,
            "MonitorArnList": [monitor_arn],
            "Subscribers": [{"Type": "SNS", "Address": topic_arn}],
            "Frequency": "IMMEDIATE",
            "ThresholdExpression": _THRESHOLD_EXPR,
        },
        ResourceTags=[{"Key": "sim2real", "Value": "tag-resource-scopes-tags-per-resource"},
                      {"Key": "owner", "Value": "subscription"}],
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_subscription(SubscriptionArn=sub_arn), "UnknownSubscriptionException"
    ))

    # Add a key to the monitor only, and a different key to the subscription only.
    ce.tag_resource(ResourceArn=monitor_arn, ResourceTags=[{"Key": "monitor-only", "Value": "x"}])
    ce.tag_resource(ResourceArn=sub_arn, ResourceTags=[{"Key": "subscription-only", "Value": "y"}])

    monitor_tags = {t["Key"]: t["Value"] for t in ce.list_tags_for_resource(ResourceArn=monitor_arn)["ResourceTags"]}
    sub_tags = {t["Key"]: t["Value"] for t in ce.list_tags_for_resource(ResourceArn=sub_arn)["ResourceTags"]}

    assert monitor_tags == {
        "sim2real": "tag-resource-scopes-tags-per-resource",
        "owner": "monitor",
        "monitor-only": "x",
    }, f"unexpected monitor tag set: {monitor_tags!r}"
    assert sub_tags == {
        "sim2real": "tag-resource-scopes-tags-per-resource",
        "owner": "subscription",
        "subscription-only": "y",
    }, f"unexpected subscription tag set: {sub_tags!r}"
    assert "subscription-only" not in monitor_tags, (
        "tagging the subscription leaked a key onto the monitor's own tag set"
    )
    assert "monitor-only" not in sub_tags, (
        "tagging the monitor leaked a key onto the subscription's own tag set"
    )

    # Remove the shared key from the monitor only; the subscription keeps it.
    ce.untag_resource(ResourceArn=monitor_arn, ResourceTagKeys=["owner"])
    monitor_tags_after = {t["Key"]: t["Value"] for t in ce.list_tags_for_resource(ResourceArn=monitor_arn)["ResourceTags"]}
    sub_tags_after = {t["Key"]: t["Value"] for t in ce.list_tags_for_resource(ResourceArn=sub_arn)["ResourceTags"]}
    assert "owner" not in monitor_tags_after, f"expected 'owner' removed from monitor, got {monitor_tags_after!r}"
    assert sub_tags_after.get("owner") == "subscription", (
        f"untagging the monitor must not affect the subscription's own 'owner' tag, got {sub_tags_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
