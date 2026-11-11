"""tag-unicode-value-round-trip."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["rds"]

_UNICODE_VALUE = "café-日本語-Москва-Zürich"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB cluster tag value with accented Latin, Cyrillic and Japanese letters reads back byte for
    byte from ListTagsForResource, as exactly one tag, on repeated reads."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-tagunicode-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    cluster = rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
    )["DBCluster"]
    cluster_arn = cluster["DBClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))

    rds.add_tags_to_resource(
        ResourceName=cluster_arn,
        Tags=[{"Key": "sim2real-unicode-tag", "Value": _UNICODE_VALUE}],
    )

    for _ in range(2):
        tags_list = rds.list_tags_for_resource(ResourceName=cluster_arn)["TagList"]
        matches = [t for t in tags_list if t["Key"] == "sim2real-unicode-tag"]
        assert len(matches) == 1, f"expected exactly one matching tag, got {matches!r}"
        assert matches[0]["Value"] == _UNICODE_VALUE, (
            f"tag value mangled: expected {_UNICODE_VALUE!r}, got {matches[0]['Value']!r}"
        )
        assert matches[0]["Value"].encode("utf-8") == _UNICODE_VALUE.encode("utf-8")
        time.sleep(1)


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _delete_cluster(ctx, cluster_id) -> None:
    rds = ctx.client("rds")
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
