"""cache-cluster-notification-configuration-names-the-topic."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-cluster-notification-configuration-names-the-topic"
GROUP = "eventing"
SERVICES = ["elasticache", "sns"]


@tags("axis:happy-path", "cap:c3", "concern:eventing", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache cluster created with an SNS topic reports that topic as its active notification
    target once available, and the topic still resolves in SNS with no subscriptions added."""
    ec = ctx.client("elasticache")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-ec-events-"), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    subnet_group = _cache_subnet_group(ctx, ec)
    cluster_id = ctx.unique_name("sim2real-ecnt-")[:40].rstrip("-")
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t4g.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[ctx.network().security_group_id],
        NotificationTopicArn=topic_arn,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ec, cluster_id))
    _wait_cluster_available(ec, cluster_id, timeout_s=1500)

    config = _wait_topic_status(ec, cluster_id, "active", timeout_s=120)
    assert config == {"TopicArn": topic_arn, "TopicStatus": "active"}, (
        f"expected the cluster to report {topic_arn!r} as its active notification topic, "
        f"got {config!r}"
    )

    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attrs["TopicArn"] == topic_arn, f"the topic reads back as {attrs!r}"
    subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert subscriptions == [], (
        f"naming the topic on a cache cluster must not subscribe anything, got {subscriptions!r}"
    )


def _wait_cluster_available(ec, cluster_id, timeout_s) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]
        if last["CacheClusterStatus"] == "available":
            return last
        time.sleep(2)
    raise AssertionError(
        f"cache cluster {cluster_id} never became available, last "
        f"{last and last['CacheClusterStatus']!r}"
    )


def _wait_topic_status(ec, cluster_id, expected, timeout_s) -> dict | None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0].get(
            "NotificationConfiguration"
        )
        if last is not None and last.get("TopicStatus") == expected:
            return last
        time.sleep(5)
    return last


def _cache_subnet_group(ctx, ec) -> str:
    """A cache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-ec-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, name))
    return name


def _delete_subnet_group(ec, name, timeout_s=1500.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheSubnetGroupNotFoundFault":
                return
            if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(15)


def _delete_cluster_when_settled(ec, cluster_id, timeout_s=1800.0) -> None:
    """Delete the cluster once it leaves its transitional state, and wait until it is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheClusterNotFound":
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(20)
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "CacheClusterNotFound":
                return
            raise
        time.sleep(20)
    raise AssertionError(f"cache cluster {cluster_id} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
