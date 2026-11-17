"""create-db-cluster-disabled-cmk-rejected-then-enabled-succeeds."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-db-cluster-disabled-cmk-rejected-then-enabled-succeeds"
GROUP = "kms-key-state-enforcement"
SERVICES = ["kms", "rds"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_KMS_FAULT = "KMSKeyNotAccessibleFault"
_DELETABLE_STATES = frozenset({"available", "backing-up"})


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


def _two_azs(ec2) -> list[str]:
    """Two available AZ names; a DB subnet group must cover at least two."""
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, f"region reports fewer than 2 available AZs: {azs!r}"
    return azs[:2]


def _subnet_group(ctx, ec2, rds) -> str:
    """A fresh VPC with one subnet in each of two AZs, grouped for RDS; teardown registered."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    subnet_ids = []
    for i, az in enumerate(_two_azs(ec2)):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.91.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(_teardown(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid),
                                 "InvalidSubnetID.NotFound"))
        subnet_ids.append(subnet_id)

    name = ctx.unique_name("sim2real-xsvc-rds-clu-subnets-")
    rds.create_db_subnet_group(DBSubnetGroupName=name,
                               DBSubnetGroupDescription="sim2real kms cluster-create check",
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


def _cluster_ids(rds) -> set[str]:
    """Every DBClusterIdentifier DescribeDBClusters currently lists, paginated in full."""
    return {c["DBClusterIdentifier"]
           for page in rds.get_paginator("describe_db_clusters").paginate()
           for c in page["DBClusters"]}


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CreateDBCluster for an encrypted Aurora cluster under a disabled CMK fails with
    KMSKeyNotAccessibleFault and leaves no cluster; once the CMK is re-enabled the identical
    call succeeds, and the cluster reads back encrypted under it.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.Keys.html
    """
    kms = ctx.client("kms")
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    key = kms.create_key(Description="sim2real kms__rds cluster-create key-state check",
                         KeyUsage="ENCRYPT_DECRYPT", Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])[
        "KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    ctx.on_cleanup(_teardown(lambda: kms.enable_key(KeyId=key_id), "KMSInvalidStateException"))

    subnet_group = _subnet_group(ctx, ec2, rds)

    cluster_id = ctx.unique_name("sim2real-xsvc-rds-clu-")
    create_args = dict(
        DBClusterIdentifier=cluster_id, Engine="aurora-postgresql", StorageEncrypted=True,
        KmsKeyId=key_arn, MasterUsername="sim2real", MasterUserPassword=secrets.token_hex(16),
        DBSubnetGroupName=subnet_group, BackupRetentionPeriod=1, DeletionProtection=False,
        Tags=_TAGS,
    )

    kms.disable_key(KeyId=key_id)
    _poll_until(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
               lambda s: s == "Disabled", timeout_s=60,
               description=f"CMK {key_id} to report KeyState=Disabled")

    code, message = _error(lambda: rds.create_db_cluster(**create_args))
    assert code == _KMS_FAULT, f"expected {_KMS_FAULT!r}, got code={code!r} message={message!r}"
    expected_create_msg = (
        f"The specified KMS key [{key_arn}] does not exist, is not enabled or you do not have "
        "permissions to access it."
    )
    assert message == expected_create_msg, f"refusal message was {message!r}"

    gone_code, gone_message = _error(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id))
    assert gone_code == "DBClusterNotFoundFault", (
        f"a CreateDBCluster refused for the key must leave no cluster; describe raised "
        f"{gone_code!r} {gone_message!r}"
    )
    assert gone_message == f"DBCluster {cluster_id} not found.", f"not-found message was {gone_message!r}"

    kms.enable_key(KeyId=key_id)
    _poll_until(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
               lambda s: s == "Enabled", timeout_s=60,
               description=f"CMK {key_id} to report KeyState=Enabled")

    created = rds.create_db_cluster(**create_args)["DBCluster"]
    ctx.on_cleanup(_teardown(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault"))
    assert created["StorageEncrypted"] is True and created["KmsKeyId"] == key_arn, (
        f"with the CMK re-enabled the identical call must be accepted, encrypted under it: "
        f"StorageEncrypted={created.get('StorageEncrypted')!r} KmsKeyId={created.get('KmsKeyId')!r}"
    )
    seen = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert seen["StorageEncrypted"] is True and seen["KmsKeyId"] == key_arn, (
        f"DescribeDBClusters must report the accepted cluster under the CMK: "
        f"StorageEncrypted={seen.get('StorageEncrypted')!r} KmsKeyId={seen.get('KmsKeyId')!r}"
    )

    # Wait here, not only in cleanup: the cleanup chain is bounded far below how long a cluster
    # takes to leave its transient state, so the delete that proves the lifecycle runs in the body.
    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"],
        lambda s: s in _DELETABLE_STATES, timeout_s=1200,
        description=f"cluster {cluster_id} to leave its transient creating state",
    )
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    _poll_until(
        lambda: cluster_id in _cluster_ids(rds),
        lambda still_listed: not still_listed, timeout_s=900,
        description=f"cluster {cluster_id} to actually disappear so the subnet group can be freed",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
