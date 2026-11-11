"""cli-rds-add-role-to-cluster-then-verify-sdk."""
from __future__ import annotations

import json
import secrets
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-add-role-to-cluster-then-verify-sdk"
GROUP = "sdk-cli-interop"
SERVICES = ["rds", "s3"]

_MANAGED_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]
#: CLI error codes RDS raises while a just-created IAM role is still propagating.
_ROLE_PROPAGATION_CODES = ("InvalidParameterValue", "IamRoleNotFoundFault")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`aws rds add-role-to-db-cluster` associates a role with an Aurora PostgreSQL cluster for
    s3Import, and DescribeDBClusters reads that association as ACTIVE."""
    require_tools("aws")

    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    rds = ctx.client("rds")

    bucket = ctx.unique_name("sim2real-rds-s3import-")
    _create_bucket(ctx, s3, bucket)

    role_name = ctx.unique_name("sim2real-rds-s3import-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "s3-import-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
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

    cluster_id = ctx.unique_name("sim2real-aurora-")
    password = "Sim2Real-" + secrets.token_hex(8)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="sim2real",
        MasterUserPassword=password,
        DatabaseName="sim2real",
        DBSubnetGroupName=_own_subnet_group(ctx),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    _wait_db_cluster_available(ctx, rds, cluster_id)

    # IAM role propagation is eventually consistent; RDS validates the role synchronously
    # against the s3Import feature, so retry the mutating call itself rather than guess a delay.
    _run_aws_with_retry(
        ctx,
        "rds",
        "add-role-to-db-cluster",
        "--db-cluster-identifier",
        cluster_id,
        "--role-arn",
        role_arn,
        "--feature-name",
        "s3Import",
    )

    associated = _poll_for_active_role(ctx, rds, cluster_id, role_arn, timeout_s=180.0)
    assert associated["Status"] == "ACTIVE", (
        f"expected s3Import association to reach ACTIVE, got {associated['Status']!r}"
    )
    assert associated["FeatureName"] == "s3Import", (
        f"expected FeatureName 's3Import', got {associated['FeatureName']!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws_with_retry(ctx, *args: str, timeout_s=30.0, retry_s=90.0, interval_s=5.0):
    """Run an aws CLI call, retrying only while it fails with a role-propagation error code."""
    deadline = time.monotonic() + retry_s
    while True:
        proc = _run_shell(
            ctx, ["aws", "--output", "json", "--no-cli-pager", *args], timeout_s=timeout_s, check=False
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        transient = any(f"({code})" in proc.stderr for code in _ROLE_PROPAGATION_CODES)
        if not transient or time.monotonic() >= deadline:
            raise AssertionError(
                f"aws {' '.join(args)} failed (rc={proc.returncode}): {proc.stderr[-500:]}"
            )
        time.sleep(interval_s)


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    if ctx.region == "us-east-1":  # us-east-1 rejects an explicit LocationConstraint
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))


def _wait_db_cluster_available(ctx, rds, cluster_id: str, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        status = resp["DBClusters"][0]["Status"]
        if status == "available":
            return resp["DBClusters"][0]
        if status in ("failed",):
            raise AssertionError(f"DB cluster entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"DB cluster {cluster_id} did not become available within {timeout_s}s")


def _poll_for_active_role(ctx, rds, cluster_id: str, role_arn: str, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_roles = []
    while time.monotonic() < deadline:
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        roles = resp["DBClusters"][0].get("AssociatedRoles", [])
        last_roles = roles
        for role in roles:
            if role["RoleArn"] == role_arn and role["Status"] == "ACTIVE":
                return role
        time.sleep(interval_s)
    raise AssertionError(
        f"role {role_arn} never reached ACTIVE on cluster {cluster_id} within {timeout_s}s; "
        f"last seen: {last_roles}"
    )


def _delete_cluster(rds, cluster_id: str, timeout_s=1200.0, interval_s=15.0) -> None:
    """Teardown: delete the cluster with no final snapshot and wait until it is gone."""
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"teardown: DB cluster {cluster_id} still exists after {timeout_s}s")


def _await_enis_clear(ec2, subnet_id, timeout_s=900, interval_s=15):
    """Wait out RDS ENIs left in a subnet of this check's own VPC after the cluster is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subnet {subnet_id} still has {len(enis)} ENI(s) after {timeout_s}s: "
                f"{[e['NetworkInterfaceId'] for e in enis]}"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, timeout_s=300, interval_s=15):
    """Run an EC2 delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _own_subnet_group(ctx):
    """A DB subnet group over a two-AZ VPC this check creates; all of it registered for cleanup."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= 2, f"region {ctx.region!r} has only {len(azs)} available AZ(s); need 2"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.195.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.195.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]

        def _drop_subnet(sid=subnet_id):
            _await_enis_clear(ec2, sid)
            _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_drop_subnet)
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
