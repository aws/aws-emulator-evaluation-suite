"""rds-s3-import-role-missing-trust-negative."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-s3-import-role-missing-trust-negative"
GROUP = "s3-import-role"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBInstance rejects a role not trusting rds.amazonaws.com with InvalidParameterValue and
    never lists it in AssociatedRoles; a correctly trusted role in the same feature slot settles to
    ACTIVE (positive control).
    """
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    instance_id = _create_pg_instance(ctx, rds)

    # Break exactly one thing: the role trusts ec2.amazonaws.com instead of
    # rds.amazonaws.com. The S3 permissions are otherwise identical to the positive
    # control role added below.
    bad_role_arn = _create_s3_import_role(ctx, iam, bucket, trust_service="ec2.amazonaws.com")
    code, message = _expect_add_role_rejected(rds, instance_id, bad_role_arn, "s3Import")
    assert code == "InvalidParameterValue", (
        f"expected AddRoleToDBInstance to reject an untrusted role with InvalidParameterValue, "
        f"got {code!r}: {message}"
    )
    assert message == (
        "IAM role ARN value is invalid or does not include the required permissions for: "
        "AWS_ROLE_INTEGRATION"
    ), f"expected the AWS_ROLE_INTEGRATION validation message, got: {message!r}"

    # Effect-absent: the rejected call never created an association to begin with.
    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    matches = [
        r
        for r in instance.get("AssociatedRoles", [])
        if r["RoleArn"] == bad_role_arn and r["FeatureName"] == "s3Import"
    ]
    assert matches == [], (
        f"expected a rejected AddRoleToDBInstance call to leave no association behind, "
        f"found {matches!r}"
    )

    # Positive control: same instance/feature slot (still empty — the rejection above left
    # nothing attached), a role that correctly trusts rds.amazonaws.com is accepted and
    # settles to ACTIVE.
    good_role_arn = _create_s3_import_role(ctx, iam, bucket, trust_service="rds.amazonaws.com")
    _add_role_with_retry(rds, instance_id, good_role_arn, "s3Import")
    ctx.on_cleanup(
        lambda: rds.remove_role_from_db_instance(
            DBInstanceIdentifier=instance_id, RoleArn=good_role_arn, FeatureName="s3Import"
        )
    )
    good_status = _wait_role_status_settled(rds, instance_id, good_role_arn, "s3Import")
    assert good_status == "ACTIVE", (
        f"expected a correctly-trusted role association to settle at ACTIVE, got {good_status!r}"
    )


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-rds-s3import-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_pg_instance(ctx, rds):
    instance_id = ctx.unique_name("sim2real-rds-s3imp-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real-" + uuid.uuid4().hex[:12],
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        StorageType="gp2",
        PubliclyAccessible=False,
        MultiAZ=False,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_db_instance_available(rds, instance_id)
    return instance_id


def _wait_db_instance_available(rds, instance_id, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return resp["DBInstances"][0]
        if status in ("failed", "incompatible-parameters", "incompatible-network"):
            raise AssertionError(f"DB instance {instance_id} entered terminal status {status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"DB instance {instance_id} did not become available within {timeout_s}s (last={status})"
    )


def _add_role_with_retry(rds, instance_id, role_arn, feature_name, timeout_s=90.0, interval_s=10.0):
    # A freshly-created IAM role is not immediately visible to RDS's own validation of the
    # association request; retry through that propagation window before accepting a
    # ClientError as durable. Only used for the positive control, where success is expected.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            rds.add_role_to_db_instance(
                DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=feature_name
            )
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _expect_add_role_rejected(rds, instance_id, role_arn, feature_name):
    try:
        rds.add_role_to_db_instance(
            DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=feature_name
        )
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    raise AssertionError(
        f"expected AddRoleToDBInstance to reject role {role_arn} (untrusted for RDS), "
        "but the call succeeded"
    )


def _create_s3_import_role(ctx, iam, bucket, *, trust_service):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-rds-s3imp-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3Import",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_role_status_settled(rds, instance_id, role_arn, feature_name, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        matches = [
            r
            for r in instance.get("AssociatedRoles", [])
            if r["RoleArn"] == role_arn and r["FeatureName"] == feature_name
        ]
        if matches:
            status = matches[0]["Status"]
            if status != "PENDING":
                return status
        time.sleep(interval_s)
    raise AssertionError(
        f"role {role_arn} association ({feature_name}) never settled past PENDING within "
        f"{timeout_s}s (last={status})"
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
