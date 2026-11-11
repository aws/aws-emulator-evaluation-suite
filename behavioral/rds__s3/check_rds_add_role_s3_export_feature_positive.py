"""rds-add-role-s3-export-feature-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "rds-add-role-s3-export-feature-positive"
GROUP = "iam-role-association"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB cluster can carry both an s3Import and an s3Export role association at
    once, each with its own distinct IAM role, and DescribeDBClusters exposes both
    feature associations independently reaching ACTIVE."""
    bucket = _create_bucket(ctx)
    _, subnet_ids = _default_vpc_subnets(ctx)
    subnet_group = _create_subnet_group(ctx, subnet_ids)
    cluster_id = _create_minimal_cluster(ctx, subnet_group)

    import_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    export_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    import_role_arn = _create_role(ctx, "rds.amazonaws.com", import_policy)
    export_role_arn = _create_role(ctx, "rds.amazonaws.com", export_policy)
    assert import_role_arn != export_role_arn, (
        f"expected two distinct IAM roles, got the same ARN twice: {import_role_arn}"
    )

    rds = ctx.client("rds")
    _add_role_with_retry(rds, cluster_id, import_role_arn, "s3Import")
    _add_role_with_retry(rds, cluster_id, export_role_arn, "s3Export")

    import_status = _poll_associated_role_status(
        rds, cluster_id, import_role_arn, "s3Import", timeout_s=300
    )
    export_status = _poll_associated_role_status(
        rds, cluster_id, export_role_arn, "s3Export", timeout_s=300
    )
    assert import_status == "ACTIVE", f"s3Import association did not reach ACTIVE: {import_status}"
    assert export_status == "ACTIVE", f"s3Export association did not reach ACTIVE: {export_status}"

    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    roles_by_feature = {r["FeatureName"]: r["RoleArn"] for r in desc.get("AssociatedRoles", [])}
    assert roles_by_feature.get("s3Import") == import_role_arn, (
        f"expected s3Import associated role {import_role_arn}, "
        f"DescribeDBClusters shows {roles_by_feature.get('s3Import')!r} "
        f"(all associated roles: {roles_by_feature!r})"
    )
    assert roles_by_feature.get("s3Export") == export_role_arn, (
        f"expected s3Export associated role {export_role_arn}, "
        f"DescribeDBClusters shows {roles_by_feature.get('s3Export')!r} "
        f"(all associated roles: {roles_by_feature!r})"
    )


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span >=2 AZs required for a DB subnet group")
    return vpc_id, list(by_az.values())[:3]


def _create_subnet_group(ctx, subnet_ids):
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _create_minimal_cluster(ctx, subnet_group):
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-cluster-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
    )
    ctx.on_cleanup(
        lambda: _delete_cluster_and_wait(rds, cluster_id)
    )
    waiter = rds.get_waiter("db_cluster_available")
    waiter.wait(DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    return cluster_id


def _create_role(ctx, trust_service, inline_policy):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
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
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if inline_policy is not None:
        pol_name = ctx.unique_name("sim2real-policy-")
        iam.put_role_policy(
            RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(inline_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))
    return arn


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-s3-")
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    else:
        s3.create_bucket(Bucket=name)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _add_role_with_retry(rds, cluster_id, role_arn, feature_name, attempts=8, delay_s=5):
    last_exc = None
    for _ in range(attempts):
        try:
            rds.add_role_to_db_cluster(
                DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
            )
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _poll_associated_role_status(rds, cluster_id, role_arn, feature_name, timeout_s=300, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        for role in desc.get("AssociatedRoles", []):
            if role["RoleArn"] == role_arn and role.get("FeatureName") == feature_name:
                last = role["Status"]
                if last in ("ACTIVE", "INVALID"):
                    return last
        time.sleep(interval_s)
    return last


def _delete_cluster_and_wait(rds, cluster_id, timeout_s=840.0):
    """Delete a DB cluster and wait until it is gone, so the subnet group it uses can be deleted."""
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBClusterNotFoundFault":
            raise
    rds.get_waiter("db_cluster_deleted").wait(
        DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
