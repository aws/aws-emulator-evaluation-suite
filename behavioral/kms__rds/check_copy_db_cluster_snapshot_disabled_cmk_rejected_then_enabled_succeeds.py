"""copy-db-cluster-snapshot-disabled-cmk-rejected-then-enabled-succeeds."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-db-cluster-snapshot-disabled-cmk-rejected-then-enabled-succeeds"
GROUP = "kms-key-state-enforcement"
SERVICES = ["kms", "rds"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_KMS_FAULT = "KMSKeyNotAccessibleFault"
_CLUSTER_DELETABLE = frozenset({"available", "backing-up"})
_SNAPSHOT_DELETABLE = frozenset({"available"})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own not-found
    codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description):
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if predicate(value):
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"{description}; last saw {value!r} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_cluster(rds, cluster_id: str) -> None:
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    # RDS deletes the cluster in the background, still using its storage key.
    rds.get_waiter("db_cluster_deleted").wait(
        DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


def _delete_cluster_snapshot(rds, snapshot_id: str) -> None:
    rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_id)
    # RDS deletes the snapshot in the background, still using its key.
    rds.get_waiter("db_cluster_snapshot_deleted").wait(
        DBClusterSnapshotIdentifier=snapshot_id, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _two_azs(ec2) -> list[str]:
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, f"region reports fewer than 2 available AZs: {azs!r}"
    return azs[:2]


def _subnet_group(ctx, ec2, rds) -> str:
    """A fresh VPC with one subnet in each of two AZs, grouped for RDS; teardown registered."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    subnet_ids = []
    for i, az in enumerate(_two_azs(ec2)):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.92.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(_teardown(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid),
                                 "InvalidSubnetID.NotFound"))
        subnet_ids.append(subnet_id)

    name = ctx.unique_name("sim2real-xsvc-rds-cps-subnets-")
    rds.create_db_subnet_group(DBSubnetGroupName=name,
                               DBSubnetGroupDescription="sim2real kms cluster-snapshot-copy check",
                               SubnetIds=subnet_ids, Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
                             "DBSubnetGroupNotFoundFault"))
    return name


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` fn() raised; raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _snapshot_ids(rds) -> set[str]:
    return {s["DBClusterSnapshotIdentifier"]
           for page in rds.get_paginator("describe_db_cluster_snapshots").paginate()
           for s in page["DBClusterSnapshots"]}


def _cluster_ids(rds) -> set[str]:
    return {c["DBClusterIdentifier"]
           for page in rds.get_paginator("describe_db_clusters").paginate()
           for c in page["DBClusters"]}


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CopyDBClusterSnapshot into an encrypted copy under a disabled CMK fails with
    KMSKeyNotAccessibleFault and leaves no target snapshot; once the CMK is re-enabled the
    identical call succeeds and the copy reads back encrypted under it.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.Keys.html
    """
    kms = ctx.client("kms")
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    key = kms.create_key(Description="sim2real kms__rds cluster-snapshot-copy key-state check",
                         KeyUsage="ENCRYPT_DECRYPT", Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])[
        "KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    ctx.on_cleanup(_teardown(lambda: kms.enable_key(KeyId=key_id), "KMSInvalidStateException"))

    # A second, always-enabled CMK for the source: Aurora refuses to add encryption on copy, so
    # the source must already be encrypted, under a DIFFERENT key than the one under test.
    source_key_arn = kms.create_key(
        Description="sim2real kms__rds cluster-snapshot-copy source key",
        KeyUsage="ENCRYPT_DECRYPT", Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(
        KeyId=source_key_arn, PendingWindowInDays=7))

    subnet_group = _subnet_group(ctx, ec2, rds)

    src_cluster_id = ctx.unique_name("sim2real-xsvc-rds-cps-src-")
    rds.create_db_cluster(DBClusterIdentifier=src_cluster_id, Engine="aurora-postgresql",
                          StorageEncrypted=True, KmsKeyId=source_key_arn,
                          MasterUsername="sim2real", MasterUserPassword=secrets.token_hex(16),
                          DBSubnetGroupName=subnet_group, BackupRetentionPeriod=1,
                          DeletionProtection=False, Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: _delete_cluster(rds, src_cluster_id), "DBClusterNotFoundFault"))
    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=src_cluster_id)["DBClusters"][0]["Status"],
        lambda s: s in _CLUSTER_DELETABLE, timeout_s=1200,
        description=f"source cluster {src_cluster_id} to leave its transient creating state",
    )

    snap_id = ctx.unique_name("sim2real-xsvc-rds-cps-snap-")
    rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id,
                                   DBClusterIdentifier=src_cluster_id, Tags=_TAGS)
    ctx.on_cleanup(_teardown(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id),
        "DBClusterSnapshotNotFoundFault"))
    source = _poll_until(
        lambda: rds.describe_db_cluster_snapshots(
            DBClusterSnapshotIdentifier=snap_id)["DBClusterSnapshots"][0],
        lambda s: s["Status"] in _SNAPSHOT_DELETABLE, timeout_s=1200,
        description=f"source snapshot {snap_id} to become available",
    )
    assert source["StorageEncrypted"] is True and source["KmsKeyId"] == source_key_arn, (
        f"the copy source must be encrypted under the SOURCE key, not the one under test; "
        f"got {source!r}"
    )
    # The snapshot is all the copy path needs; stop paying for the source cluster now.
    rds.delete_db_cluster(DBClusterIdentifier=src_cluster_id, SkipFinalSnapshot=True)
    _poll_until(lambda: src_cluster_id in _cluster_ids(rds), lambda still: not still, timeout_s=900,
               description=f"source cluster {src_cluster_id} to actually disappear")

    kms.disable_key(KeyId=key_id)
    _poll_until(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
               lambda s: s == "Disabled", timeout_s=60,
               description=f"CMK {key_id} to report KeyState=Disabled")

    copy_id = ctx.unique_name("sim2real-xsvc-rds-cps-copy-")
    copy_args = dict(SourceDBClusterSnapshotIdentifier=snap_id,
                     TargetDBClusterSnapshotIdentifier=copy_id, KmsKeyId=key_arn, Tags=_TAGS)
    code, message = _error(lambda: rds.copy_db_cluster_snapshot(**copy_args))
    assert code == _KMS_FAULT, f"expected {_KMS_FAULT!r}, got code={code!r} message={message!r}"
    expected_msg = (
        f"Specified KMS key [{key_arn}] does not exist, is not enabled or you do not have "
        "permissions to access it."
    )
    assert message == expected_msg, f"refusal message was {message!r}"

    gone_code, gone_message = _error(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=copy_id))
    assert gone_code == "DBClusterSnapshotNotFoundFault", (
        f"a CopyDBClusterSnapshot refused for the key must leave no target snapshot; describe "
        f"raised {gone_code!r} {gone_message!r}"
    )
    assert gone_message == f"DBClusterSnapshot not found: {copy_id}", (
        f"not-found message was {gone_message!r}"
    )

    kms.enable_key(KeyId=key_id)
    _poll_until(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
               lambda s: s == "Enabled", timeout_s=60,
               description=f"CMK {key_id} to report KeyState=Enabled")

    copied = rds.copy_db_cluster_snapshot(**copy_args)["DBClusterSnapshot"]
    ctx.on_cleanup(_teardown(lambda: _delete_cluster_snapshot(rds, copy_id),
                             "DBClusterSnapshotNotFoundFault"))
    assert copied["DBClusterSnapshotIdentifier"] == copy_id, f"copy returned {copied!r}"
    target = _poll_until(
        lambda: rds.describe_db_cluster_snapshots(
            DBClusterSnapshotIdentifier=copy_id)["DBClusterSnapshots"][0],
        lambda s: s["Status"] in _SNAPSHOT_DELETABLE, timeout_s=1200,
        description=f"copy {copy_id} to become available",
    )
    assert target["StorageEncrypted"] is True and target["KmsKeyId"] == key_arn, (
        f"the copy made with KmsKeyId=<CMK> must be encrypted under it; "
        f"StorageEncrypted={target.get('StorageEncrypted')!r} KmsKeyId={target.get('KmsKeyId')!r}"
    )
    src_after = rds.describe_db_cluster_snapshots(
        DBClusterSnapshotIdentifier=snap_id)["DBClusterSnapshots"][0]
    assert src_after["KmsKeyId"] == source_key_arn, (
        f"copying must not mutate the source snapshot's own key: {src_after['KmsKeyId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
