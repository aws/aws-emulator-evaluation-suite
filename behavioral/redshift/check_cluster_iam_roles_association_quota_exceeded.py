"""cluster-iam-roles-association-quota-exceeded."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-iam-roles-association-quota-exceeded"
GROUP = "overly-permissive"
SERVICES = ["ec2", "iam", "redshift"]

ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_IN_USE = ("InvalidClusterSubnetGroupStateFault", "DependencyViolation", "InvalidClusterState")
ASSOCIATED_ROLES = 50  # the documented, non-adjustable ceiling


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _expect_error(fn):
    """Call *fn*, which must fail with an AWS error; return its exact (code, message)."""
    try:
        result = _retrying(fn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_until(probe, done, timeout_s, interval_s, what):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


def _node_type_and_az(rs, ec2):
    offered = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    azs_by_type = {}
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != "single-node":
                continue
            nt = opt.get("NodeType")
            if not nt:
                continue
            azs = azs_by_type.setdefault(nt, [])
            for az in opt.get("AvailabilityZones", []):
                if az.get("Name") in offered and az["Name"] not in azs:
                    azs.append(az["Name"])
        marker = resp.get("Marker")
        if not marker:
            break
    for preferred in ("dc2.large", "ra3.large", "ra3.xlplus"):
        if azs_by_type.get(preferred):
            return preferred, sorted(azs_by_type[preferred])[0]
    usable = {nt: azs for nt, azs in azs_by_type.items() if azs}
    assert usable, "no single-node orderable cluster option offers an available AZ"
    nt = sorted(usable)[0]
    return nt, sorted(usable[nt])[0]


def _create_subnet_group(ctx, rs, ec2, az):
    tags = [{"Key": "sim2real-behavioral", "Value": "true"}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id), f"vpc {vpc_id}"))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.92.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_retrying(lambda: ec2.delete_subnet(SubnetId=subnet_id), f"subnet {subnet_id}")
    )
    group_name = ctx.unique_name("sim2real-behav-rs-iamsg-")
    rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="sim2real behavioral check",
        SubnetIds=[subnet_id],
        Tags=tags,
    )
    ctx.on_cleanup(
        lambda: _delete_retrying(
            lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=group_name),
            f"cluster subnet group {group_name}",
        )
    )
    return group_name


def _delete_retrying(fn, what, timeout_s=180, interval_s=2):
    deadline = time.time() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code.endswith("NotFound") or code.endswith("NotFoundFault") or ".NotFound" in code:
                return
            if code not in _IN_USE and code != "NoSuchEntity":
                raise
            if time.time() >= deadline:
                raise AssertionError(f"could not delete {what}: {code}") from exc
        time.sleep(interval_s)


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600):
    terminal = {"available", "incompatible-network", "insufficient-capacity", "hardware-failure", None}
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=15,
        what=f"cluster {cluster_id} available",
    )
    assert status == "available", f"cluster {cluster_id} reached {status!r}, expected 'available'"


def _describe_cluster(rs, cluster_id):
    resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    return resp["Clusters"][0]


def _wait_for_roles_in_sync(rs, cluster_id, timeout_s=300):
    def _statuses():
        return {r["IamRoleArn"]: r["ApplyStatus"] for r in _describe_cluster(rs, cluster_id)["IamRoles"]}

    return _wait_until(
        _statuses,
        lambda statuses: statuses and all(v == "in-sync" for v in statuses.values()),
        timeout_s=timeout_s,
        interval_s=10,
        what=f"every IAM role on {cluster_id} to reach in-sync",
    )


def _delete_cluster_and_wait(rs, cluster_id):
    deadline = time.time() + 240
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.time() >= deadline:
                raise
            time.sleep(5)
    _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s is None,
        timeout_s=900,
        interval_s=20,
        what=f"cluster {cluster_id} to disappear",
    )


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "redshift.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyClusterIamRoles associates up to the documented 50-role ceiling per cluster and
    rejects the 51st, leaving the cluster's associated roles unchanged.

    Reference: https://docs.aws.amazon.com/help-panel/redshift/latest/console/hp-cluster_associated_iam-roles.html
    """
    rs = ctx.client("redshift")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    node_type, az = _node_type_and_az(rs, ec2)
    subnet_group_name = _create_subnet_group(ctx, rs, ec2, az)

    cluster_id = ctx.unique_name("sim2real-behav-rs-iamq-")
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rs, cluster_id))
    rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=node_type,
        ClusterSubnetGroupName=subnet_group_name,
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        # RA3 node types refuse a 0-day retention period; use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    _wait_for_cluster_available(rs, cluster_id, timeout_s=420)

    role_arns = []
    for i in range(ASSOCIATED_ROLES + 1):
        role_name = ctx.unique_name(f"sim2real-behav-rs-iamq-role-{i}-")
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]
        ctx.on_cleanup(lambda name=role_name: _delete_retrying(
            lambda: iam.delete_role(RoleName=name), f"iam role {name}"
        ))
        role_arns.append(role["Arn"])

    # Positive control: associating exactly the documented ceiling (50 roles) succeeds.
    at_ceiling = role_arns[:ASSOCIATED_ROLES]
    added = _retrying(
        lambda: rs.modify_cluster_iam_roles(ClusterIdentifier=cluster_id, AddIamRoles=at_ceiling)
    )["Cluster"]
    assert len(added["IamRoles"]) == ASSOCIATED_ROLES, (
        f"expected {ASSOCIATED_ROLES} associated roles, got {len(added['IamRoles'])}"
    )
    _wait_for_roles_in_sync(rs, cluster_id)

    # Break exactly one thing: the 51st role pushes the cluster one past the ceiling.
    over_ceiling_role = role_arns[ASSOCIATED_ROLES]
    code, message = _expect_error(
        lambda: rs.modify_cluster_iam_roles(
            ClusterIdentifier=cluster_id, AddIamRoles=[over_ceiling_role]
        )
    )
    assert code == "InvalidParameterValue", (
        f"associating a 51st IAM role must be rejected, got {code}"
    )
    expected_message = (
        f"Cluster already has {ASSOCIATED_ROLES} IAM Roles. Only 0 new IAM Role(s) may be "
        "added to this Cluster."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the rejected 51st role never joined the cluster's role list.
    after_rejection = _describe_cluster(rs, cluster_id)
    after_arns = {r["IamRoleArn"] for r in after_rejection["IamRoles"]}
    assert over_ceiling_role not in after_arns, (
        f"the rejected role {over_ceiling_role!r} must not appear in the cluster's IAM roles"
    )
    assert after_arns == set(at_ceiling), (
        f"expected exactly the {ASSOCIATED_ROLES} roles at the ceiling, got {len(after_arns)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
