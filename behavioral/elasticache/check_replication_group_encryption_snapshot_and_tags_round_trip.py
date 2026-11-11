"""replication-group-encryption-snapshot-and-tags-round-trip."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _poll(probe, predicate, timeout_s=1800, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _describe_rg(ec, rg_id):
    try:
        return ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    except ClientError as e:
        if "NotFound" in (e.response.get("Error", {}).get("Code") or ""):
            return None
        raise

def _delete_rg_if_present(ec, rg_id):
    """Teardown: the body already deletes the group on its happy path; not-found is done."""
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as e:
        if "NotFound" not in (e.response.get("Error", {}).get("Code") or ""):
            raise

def _wait_rg_status(ec, rg_id, status, timeout_s=1800, interval_s=15):
    return _poll(lambda: _describe_rg(ec, rg_id),
                 lambda rg: rg is not None and rg.get("Status") == status,
                 timeout_s, interval_s)

CHECK = "replication-group-encryption-snapshot-and-tags-round-trip"
GROUP = 'replication-group'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replication group created with KMS at-rest encryption, a snapshot schedule and tags
    reads them all back; ModifyReplicationGroup's snapshot change persists in a later describe
    while the encryption and KMS key survive the modify."""
    ec = ctx.client("elasticache")
    kms = ctx.client("kms")
    rg_id = ctx.unique_name("sim2real-behav-ecrg-enc-")

    key = kms.create_key(Description=rg_id,
                         Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]

    def _cleanup_key():
        try:
            kms.delete_alias(AliasName=f"alias/{rg_id}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)

    ctx.on_cleanup(_cleanup_key)
    kms.create_alias(AliasName=f"alias/{rg_id}", TargetKeyId=key_id)

    subnet_group = _network_cache_subnet_group(ctx, ec)
    created = ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real encryption/snapshot/tags round trip",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AtRestEncryptionEnabled=True,
        KmsKeyId=f"alias/{rg_id}",
        SnapshotRetentionLimit=7,
        SnapshotWindow="06:30-07:30",
        Tags=[{"Key": "Name", "Value": rg_id}, {"Key": "sim2real", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )["ReplicationGroup"]
    ctx.on_cleanup(lambda: _delete_rg_if_present(ec, rg_id))
    assert created["Status"] == "creating", created["Status"]

    rg = _wait_rg_status(ec, rg_id, "available")
    assert rg["AtRestEncryptionEnabled"] is True, rg
    assert rg["KmsKeyId"] == key_arn, (rg["KmsKeyId"], key_arn)
    assert rg["SnapshotRetentionLimit"] == 7, rg
    assert rg["SnapshotWindow"] == "06:30-07:30", rg
    rg_arn = rg["ARN"]
    assert rg_arn.endswith(f"replicationgroup:{rg_id}"), rg_arn

    tag_list = ec.list_tags_for_resource(ResourceName=rg_arn)["TagList"]
    assert any(t["Key"] == "Name" and t["Value"] == rg_id for t in tag_list), (
        f"ListTagsForResource on {rg_arn!r} lacks Name={rg_id!r}: {tag_list!r}")

    modified = ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        SnapshotRetentionLimit=3,
        SnapshotWindow="01:00-02:00",
        ApplyImmediately=True,
    )["ReplicationGroup"]
    assert modified["SnapshotRetentionLimit"] == 3, modified
    assert modified["SnapshotWindow"] == "01:00-02:00", modified

    reread = _poll(
        lambda: _describe_rg(ec, rg_id),
        lambda rg: rg is not None and rg.get("SnapshotRetentionLimit") == 3,
        timeout_s=300, interval_s=10,
    )
    assert reread["SnapshotWindow"] == "01:00-02:00", reread
    # At-rest encryption and its KMS key are immutable after create.
    assert reread["AtRestEncryptionEnabled"] is True, reread
    assert reread["KmsKeyId"] == key_arn, reread["KmsKeyId"]

    ec.delete_replication_group(ReplicationGroupId=rg_id)
    _poll(lambda: _describe_rg(ec, rg_id), lambda rg: rg is None,
          timeout_s=1800, interval_s=15)


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
            # DeleteCacheSubnetGroup refuses a group a cluster still holds with CacheSubnetGroupInUse.
            ("CacheSubnetGroupInUse", "InvalidCacheSubnetGroupState"),
            ("CacheSubnetGroupNotFoundFault",),
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
