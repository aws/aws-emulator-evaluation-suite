"""rds-remove-iam-role-association-stops-s3-access-negative."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-remove-iam-role-association-stops-s3-access-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After RemoveRoleFromDBInstance the s3Import association is gone, a second remove is rejected with
    DBInstanceRoleNotFound, and re-adding the same role and feature reaches ACTIVE."""
    bucket = _create_bucket(ctx)
    role_arn = _create_iam_role(
        ctx,
        trust_principal="rds.amazonaws.com",
        policy_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
        name_prefix="sim2real-rds-removerole-role-",
    )
    db_id, _arn = _create_db_instance(ctx)

    rds = ctx.client("rds")

    # Setup: associate and confirm it is ACTIVE.
    rds.add_role_to_db_instance(DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Import")
    entry = _poll_role_entry_active(ctx, db_id, role_arn, "s3Import", timeout_s=300.0)
    assert entry is not None and entry["Status"] == "ACTIVE", f"expected ACTIVE role association, got {entry}"

    # Break: remove the association.
    rds.remove_role_from_db_instance(DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Import")
    gone = _poll_role_entry_absent(ctx, db_id, role_arn, "s3Import", timeout_s=300.0)
    assert gone, "s3Import association still present in AssociatedRoles after removal"

    # Removing an association that no longer exists fails with the specific not-found error.
    error = _client_error(
        lambda: rds.remove_role_from_db_instance(
            DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Import"
        )
    )
    assert error.get("Code") == "DBInstanceRoleNotFound", error
    expected_message = (
        f"The {role_arn} IAM role doesn't match with the s3Import feature for the {db_id} "
        "DB instance. Check and try again."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: the same role/feature pair can be re-added successfully.
    rds.add_role_to_db_instance(DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Import")
    re_entry = _poll_role_entry_active(ctx, db_id, role_arn, "s3Import", timeout_s=300.0)
    assert re_entry is not None and re_entry["Status"] == "ACTIVE", (
        f"expected re-added role association to become ACTIVE again, got {re_entry}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises, so a
    target that accepts what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _create_iam_role(
    ctx: Any, trust_principal: str, policy_statements: list[dict[str, Any]], name_prefix: str
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    policy_doc = {"Version": "2012-10-17", "Statement": policy_statements}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_db_instance(ctx: Any) -> tuple[str, str]:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-s3-")
    password = "Pg1" + secrets.token_hex(8) + "Aa"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="pgadmin1",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        MultiAZ=False,
        BackupRetentionPeriod=0,
        StorageType="gp2",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True))
    instance = _wait_db_available(ctx, db_id)
    return db_id, instance["DBInstanceArn"]


def _wait_db_available(ctx: Any, db_id: str, timeout_s: float = 1800.0, interval_s: float = 15.0) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instance = resp["DBInstances"][0]
        status = instance["DBInstanceStatus"]
        if status == "available":
            return instance
        if status in ("failed", "incompatible-restore", "incompatible-network"):
            raise AssertionError(f"DB instance entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"DB instance {db_id} did not become available within {timeout_s}s")


def _find_role_entry(instance_desc: dict, role_arn: str, feature_name: str) -> dict | None:
    for entry in instance_desc.get("AssociatedRoles", []):
        if entry.get("RoleArn") == role_arn and entry.get("FeatureName") == feature_name:
            return entry
    return None


def _poll_role_entry_active(
    ctx: Any, db_id: str, role_arn: str, feature_name: str, timeout_s: float = 300.0, interval_s: float = 10.0
) -> dict | None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        entry = _find_role_entry(resp["DBInstances"][0], role_arn, feature_name)
        last = entry
        if entry is not None and entry.get("Status") == "ACTIVE":
            return entry
        time.sleep(interval_s)
    return last


def _poll_role_entry_absent(
    ctx: Any, db_id: str, role_arn: str, feature_name: str, timeout_s: float = 300.0, interval_s: float = 10.0
) -> bool:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        entry = _find_role_entry(resp["DBInstances"][0], role_arn, feature_name)
        if entry is None:
            return True
        time.sleep(interval_s)
    return False


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
