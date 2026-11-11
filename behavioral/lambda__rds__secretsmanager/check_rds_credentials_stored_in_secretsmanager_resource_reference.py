"""rds-credentials-stored-in-secretsmanager-resource-reference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from typing import Any

from behavioral_harness import tags

CHECK = "rds-credentials-stored-in-secretsmanager-resource-reference"
GROUP = "resource-binding"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DB instance created with an RDS-managed admin password stores username/password in an
    RDS-owned secret whose DescribeSecret reports OwningService="rds" and an
    aws:rds:primaryDBInstanceArn tag equal to the instance ARN."""
    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")

    db_id = ctx.unique_name("sim2real-behav-dbi-")
    master_username = "admin"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername=master_username,
        ManageMasterUserPassword=True,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    )

    instance = _wait_for_instance_available(ctx, db_id, timeout_s=1200.0)
    secret_arn = instance["MasterUserSecret"]["SecretArn"]
    instance_arn = instance["DBInstanceArn"]

    secret_value = sm.get_secret_value(SecretId=secret_arn)
    import json

    payload = json.loads(secret_value["SecretString"])

    assert payload["username"] == master_username, (
        f"secret {secret_arn} username {payload.get('username')!r} != master username "
        f"{master_username!r}"
    )
    assert payload["password"], f"secret {secret_arn} carries no password: keys {sorted(payload)!r}"

    # Cross-check the reverse lookup: the secret's own metadata ties it back to THIS RDS instance.
    secret_desc = sm.describe_secret(SecretId=secret_arn)
    assert secret_desc["ARN"] == secret_arn, (
        f"DescribeSecret ARN {secret_desc.get('ARN')!r} != the SecretArn RDS reported "
        f"({secret_arn!r})"
    )
    owning_service = secret_desc.get("OwningService")
    assert owning_service == "rds", (
        f"secret {secret_arn} OwningService {owning_service!r} != 'rds' — it should be owned by "
        f"RDS, not created independently"
    )
    tag_map = {t["Key"]: t["Value"] for t in secret_desc.get("Tags", [])}
    binding_tag = tag_map.get("aws:rds:primaryDBInstanceArn")
    assert binding_tag == instance_arn, (
        f"expected the RDS-managed secret {secret_arn} to carry an "
        f"'aws:rds:primaryDBInstanceArn' tag equal to {instance_arn!r}; got {binding_tag!r} "
        f"(tags={tag_map!r})"
    )


# ===== helpers =====


def _wait_for_instance_available(ctx: Any, db_id: str, timeout_s: float = 1200.0) -> dict:
    """Poll until the instance is 'available' AND its managed secret has settled to
    'active' — SecretArn can appear while SecretStatus is still 'creating', and
    GetSecretValue against a not-yet-active managed secret does not yet carry the full
    document."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_status = None
    last_secret_status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instance = resp["DBInstances"][0]
        last_status = instance["DBInstanceStatus"]
        secret = instance.get("MasterUserSecret") or {}
        last_secret_status = secret.get("SecretStatus")
        if last_status == "available" and secret.get("SecretArn") and last_secret_status == "active":
            return instance
        time.sleep(2)
    raise AssertionError(
        f"DB instance {db_id} never reached available+active-secret "
        f"(last status={last_status!r}, last secret status={last_secret_status!r})"
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
