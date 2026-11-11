"""storage-encrypted-without-kms-key-uses-aws-managed-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "storage-encrypted-without-kms-key-uses-aws-managed-key"
GROUP = "instance_lifecycle"
SERVICES = ["kms", "rds"]


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_instance(rds, ident):
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=ident)
        insts = resp.get("DBInstances", [])
        return insts[0] if insts else None
    except ClientError:
        return None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance(StorageEncrypted=True) with no KmsKeyId resolves to the AWS managed key
    for Amazon RDS: the key's KeyManager is 'AWS' and alias/aws/rds maps to it.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
    """
    rds = ctx.client("rds")
    kms = ctx.client("kms")
    ident = ctx.unique_name("sim2real-behav-dbi-")
    rds.create_db_instance(
        DBInstanceIdentifier=ident,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        AllocatedStorage=20,
        StorageEncrypted=True,
        BackupRetentionPeriod=1,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=ident, SkipFinalSnapshot=True, DeleteAutomatedBackups=True), "DBInstanceNotFound"))
    inst = _poll_until(
        lambda: _describe_instance(rds, ident),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} available",
    )
    assert inst["StorageEncrypted"] is True, (
        f"expected StorageEncrypted True, got {inst['StorageEncrypted']!r}"
    )
    key_arn = inst["KmsKeyId"]
    assert key_arn.startswith(f"arn:aws:kms:{ctx.region}:{ctx.account}:key/"), (
        f"expected a key ARN in this account and region, got {key_arn!r}"
    )

    seen = rds.describe_db_instances(DBInstanceIdentifier=ident)["DBInstances"][0]
    assert seen["KmsKeyId"] == key_arn, (
        f"DescribeDBInstances must report the same resolved key; got {seen['KmsKeyId']!r}, "
        f"expected {key_arn!r}"
    )

    key_id = key_arn.rsplit("/", 1)[-1]
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyManager"] == "AWS", (
        f"the key behind an unspecified KmsKeyId must be AWS-managed, got KeyManager {meta['KeyManager']!r}"
    )
    aliases = {a["AliasName"]: a["TargetKeyId"] for a in kms.list_aliases(KeyId=key_id)["Aliases"]}
    assert "alias/aws/rds" in aliases, (
        f"expected the resolved key to carry alias/aws/rds, got aliases {sorted(aliases)!r}"
    )
    assert aliases["alias/aws/rds"] == key_id, (
        f"expected alias/aws/rds to map to {key_id!r}, got {aliases['alias/aws/rds']!r}"
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
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.
    The 1500 s default window fits within the suite's 1800 s teardown budget."""
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


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
