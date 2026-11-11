"""iam-role-trust-s3-service-for-rds-integration-positive."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-s3-service-for-rds-integration-positive"
GROUP = "iam-trust"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBInstance(s3Import) rejects a role trusting s3.amazonaws.com with
    InvalidParameterValue at call time and leaves no AssociatedRoles entry, while a role with the
    same S3 permissions trusting rds.amazonaws.com settles ACTIVE before and after the rejection."""
    bucket = _create_bucket(ctx)
    db_id, _arn = _create_db_instance(ctx)
    rds = ctx.client("rds")

    # The wrongly-trusted role is created first, so the good role's acceptance below shows it
    # has propagated by the time it is rejected.
    bad_role_arn = _create_iam_role(
        ctx,
        trust_principal="s3.amazonaws.com",
        policy_statements=_s3_read_statements(bucket),
        name_prefix="sim2real-rds-wrongtrust-role-",
    )
    good_role_arn = _create_iam_role(
        ctx,
        trust_principal="rds.amazonaws.com",
        policy_statements=_s3_read_statements(bucket),
        name_prefix="sim2real-rds-goodtrust-role-",
    )

    # Positive control: the account and the s3Import feature slot are otherwise healthy.
    _add_role_when_propagated(ctx, rds, db_id, good_role_arn)
    good_entry = _poll_role_entry_settled(ctx, db_id, good_role_arn, "s3Import")
    assert good_entry["Status"] == "ACTIVE", (
        f"positive control: correctly-trusted role expected ACTIVE, got {good_entry['Status']!r}"
    )

    # Free the s3Import slot so the broken attempt below has a clean instance to be rejected on.
    rds.remove_role_from_db_instance(DBInstanceIdentifier=db_id, RoleArn=good_role_arn, FeatureName="s3Import")
    _wait_role_absent(ctx, db_id, good_role_arn, "s3Import")

    # Break exactly one thing: trust s3.amazonaws.com instead of rds.amazonaws.com.
    code, message = _error_code(
        lambda: rds.add_role_to_db_instance(
            DBInstanceIdentifier=db_id, RoleArn=bad_role_arn, FeatureName="s3Import"
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a role trusting s3.amazonaws.com, got {code!r}"
    )
    assert message == (
        "IAM role ARN value is invalid or does not include the required permissions for: "
        "AWS_ROLE_INTEGRATION"
    ), f"unexpected InvalidParameterValue message: {message!r}"

    # Effect absent: the rejected call must never leave an AssociatedRoles entry behind.
    instance = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    assert _find_role_entry(instance, bad_role_arn, "s3Import") is None, (
        "AddRoleToDBInstance raised InvalidParameterValue but an AssociatedRoles entry "
        "for the rejected role appeared anyway"
    )

    # Restore: the identical call that worked before the broken attempt works again.
    rds.add_role_to_db_instance(DBInstanceIdentifier=db_id, RoleArn=good_role_arn, FeatureName="s3Import")
    restored_entry = _poll_role_entry_settled(ctx, db_id, good_role_arn, "s3Import")
    assert restored_entry["Status"] == "ACTIVE", (
        f"restore: correctly-trusted role expected ACTIVE again, got {restored_entry['Status']!r}"
    )
    ctx.on_cleanup(
        lambda: rds.remove_role_from_db_instance(
            DBInstanceIdentifier=db_id, RoleArn=good_role_arn, FeatureName="s3Import"
        )
    )


# ===== helpers =====


def _s3_read_statements(bucket: str) -> list[dict[str, Any]]:
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ]


def _error_code(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _add_role_when_propagated(ctx: Any, rds, db_id: str, role_arn: str, timeout_s: float = 120.0) -> None:
    """Add the role for s3Import, retrying the error RDS returns until a new IAM role propagates."""
    budget = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if budget is None else min(timeout_s, budget))
    while True:
        try:
            rds.add_role_to_db_instance(DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Import")
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"AddRoleToDBInstance kept rejecting the rds.amazonaws.com-trusted role {role_arn} "
                    f"for {timeout_s}s: {exc.response['Error'].get('Message', '')!r}"
                ) from exc
        time.sleep(2)


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
    # there, so the literal is a required special case of the API, not a region pin.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
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


def _poll_role_entry_settled(
    ctx: Any, db_id: str, role_arn: str, feature_name: str, timeout_s: float = 300.0, interval_s: float = 10.0
) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        entry = _find_role_entry(resp["DBInstances"][0], role_arn, feature_name)
        if entry is not None:
            last = entry
            if entry["Status"] != "PENDING":
                return entry
        time.sleep(interval_s)
    raise AssertionError(
        f"role association ({role_arn}, {feature_name}) never settled past PENDING within "
        f"{timeout_s}s (last={last!r})"
    )


def _wait_role_absent(
    ctx: Any, db_id: str, role_arn: str, feature_name: str, timeout_s: float = 120.0, interval_s: float = 10.0
) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        if _find_role_entry(instance, role_arn, feature_name) is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"role {role_arn} ({feature_name}) still associated after removal request")


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
