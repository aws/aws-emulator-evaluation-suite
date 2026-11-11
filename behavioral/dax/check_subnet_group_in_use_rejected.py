"""subnet-group-in-use-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_TIMEOUT_S = 1500.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSubnetGroup is rejected with SubnetGroupInUseFault while a DAX cluster
    still references it -- the subnet group is left in place -- and deleting the same
    subnet group (the positive control) succeeds once the referencing cluster is gone."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _own_vpc_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    _create_cluster_with_role_propagation_retry(
        dax,
        ClusterName=cluster_name,
        NodeType=_NODE_TYPE,
        ReplicationFactor=1,
        IamRoleArn=role_arn,
        SubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))

    code, message = _expect_error(lambda: dax.delete_subnet_group(SubnetGroupName=subnet_group_name))
    assert code == "SubnetGroupInUseFault", (
        f"deleting a subnet group referenced by cluster {cluster_name!r} returned {code!r}, "
        f"not SubnetGroupInUseFault"
    )
    assert message == f"Subnet group {subnet_group_name} is currently in use by a cluster.", (
        f"unexpected message: {message!r}"
    )

    still_there = dax.describe_subnet_groups(SubnetGroupNames=[subnet_group_name])["SubnetGroups"][0]
    assert still_there["SubnetGroupName"] == subnet_group_name, (
        f"subnet group {subnet_group_name!r} should still exist after the rejected delete, "
        f"got {still_there!r}"
    )

    _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["Status"] == "available",
        timeout_s=_TIMEOUT_S,
    )
    dax.delete_cluster(ClusterName=cluster_name)
    _poll_until(
        lambda: _cluster_gone(dax, cluster_name),
        lambda gone: gone,
        timeout_s=_TIMEOUT_S,
    )

    dax.delete_subnet_group(SubnetGroupName=subnet_group_name)
    gone_code, gone_message = _expect_error(
        lambda: dax.describe_subnet_groups(SubnetGroupNames=[subnet_group_name])
    )
    assert gone_code == "SubnetGroupNotFoundFault", (
        f"describing subnet group {subnet_group_name!r} after its delete (now that the "
        f"referencing cluster is gone) returned {gone_code!r}, not SubnetGroupNotFoundFault"
    )
    assert gone_message == f"Subnet group {subnet_group_name} not found.", (
        f"unexpected message: {gone_message!r}"
    )


# ===== helpers =====
def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target accepting what AWS refuses must not be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cluster_gone(dax, cluster_name):
    """Existence probe: True once DescribeClusters reports ClusterNotFoundFault."""
    try:
        dax.describe_clusters(ClusterNames=[cluster_name])
    except ClientError as err:
        return err.response["Error"]["Code"] == "ClusterNotFoundFault"
    return False


def _describe_cluster(ctx, cluster_name):
    return ctx.client("dax").describe_clusters(ClusterNames=[cluster_name])["Clusters"][0]


def _poll_until(probe, predicate, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _own_vpc_subnet_ids(ctx, count=2):
    # No dependence on an ambient default VPC: a freshly provisioned account may not have
    # one, so this check provisions and tears down its own network.
    ec2 = ctx.client("ec2")
    marker = [{"Key": "sim2real-check", "Value": CHECK}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": marker}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
        lambda v: v["State"] == "available",
        timeout_s=60.0,
        interval_s=5.0,
    )

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:count]
    if len(azs) < count:
        raise AssertionError(f"region {ctx.region!r} has fewer than {count} available availability zones")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.90.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": marker}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ctx, sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _safe_delete_subnet(ctx, subnet_id, deadline_s=120.0, interval_s=2.0):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            return
        except ClientError as err:
            # A lingering ENI from the just-deleted cluster blocks the subnet delete for a
            # bounded window after DeleteCluster returns; retry it to the deadline, then raise.
            code = err.response["Error"]["Code"]
            if code == "InvalidSubnetID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_delete_vpc(ctx, vpc_id, deadline_s=120.0, interval_s=2.0):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_subnet_group(ctx, subnet_ids):
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))
    return name


def _safe_delete_subnet_group(ctx, name, deadline_s=300.0, interval_s=2.0):
    # The cluster deletes asynchronously and holds the group (SubnetGroupInUseFault) until it is gone.
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            ctx.client("dax").delete_subnet_group(SubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ServiceLinkedRoleNotFoundFault", "SubnetGroupNotFoundFault"):
                return
            if code != "SubnetGroupInUseFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_dax_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dax-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "dax.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    access_policy = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    iam.put_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access", PolicyDocument=access_policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_cluster_with_role_propagation_retry(dax, deadline_s=60.0, interval_s=5.0, **kwargs):
    # A just-created IAM role is not always immediately assumable by DAX; retry the bounded
    # window instead of a fixed sleep, so a genuinely broken request still fails loudly.
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return dax.create_cluster(**kwargs)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_delete_cluster(ctx, cluster_name, deadline_s=300.0, interval_s=2.0):
    # DeleteCluster refuses a cluster still changing state (InvalidClusterStateFault); retry that to the deadline.
    dax = ctx.client("dax")
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            dax.delete_cluster(ClusterName=cluster_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ClusterNotFoundFault", "ServiceLinkedRoleNotFoundFault"):
                return
            if code != "InvalidClusterStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
