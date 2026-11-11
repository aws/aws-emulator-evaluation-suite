"""rds-associate-role-wrong-feature-name-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-associate-role-wrong-feature-name-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]
_ROLE_NOT_VISIBLE_MESSAGE = (
    "IAM role ARN value is invalid or does not include the required permissions for: "
    "AWS_ROLE_INTEGRATION"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBCluster with an unrecognized FeatureName is rejected with InvalidParameterValue and
    leaves AssociatedRoles empty, and the same role with s3Import then reaches ACTIVE."""
    bucket = _create_bucket(ctx)
    _, subnet_ids = _default_vpc_subnets(ctx)
    subnet_group = _create_subnet_group(ctx, subnet_ids)
    cluster_id = _create_minimal_cluster(ctx, subnet_group)
    rds = ctx.client("rds")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    role_arn = _create_role(ctx, "rds.amazonaws.com", policy)

    # Break exactly one thing: an unrecognized feature name string.
    bad_feature = "NotARealFeatureXYZ"
    # A role created seconds earlier is not yet visible to RDS, which answers with the same
    # code but the role-validation message; wait that propagation window out so the answer
    # graded below is the feature-name validation itself.
    deadline = time.monotonic() + 120
    while True:
        error = _client_error(
            lambda: rds.add_role_to_db_cluster(
                DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=bad_feature
            )
        )
        if error.get("Message") != _ROLE_NOT_VISIBLE_MESSAGE or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert error.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    expected_message = f"The feature name {bad_feature} is not valid for the engine Aurora (PostgreSQL)."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert desc.get("AssociatedRoles", []) == [], "no association should have been created"

    # Positive control in the same file: the identical role with a valid feature
    # name is accepted and reaches ACTIVE on the same cluster.
    _add_role_with_retry(rds, cluster_id, role_arn, "s3Import")
    status = _poll_associated_role_status(rds, cluster_id, role_arn, "s3Import", timeout_s=300)
    assert status == "ACTIVE", f"expected valid feature name association to reach ACTIVE, got {status}"


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING an input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
        Tags=_TAGS,
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
        MasterUserPassword="Sim2RealTest1234!",
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
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
    resp = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS
    )
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
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
    raise AssertionError(
        f"role association for {feature_name} did not reach a terminal status within "
        f"{timeout_s}s (last saw {last!r})"
    )


def _delete_cluster_and_wait(rds, cluster_id, timeout_s=900, interval_s=15):
    """Delete the cluster and block until it is gone, so the subnet group teardown that
    runs next does not find the cluster still holding it."""
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} was not deleted within {timeout_s}s")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
