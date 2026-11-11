"""delete-cluster-while-creating-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-while-creating-rejected"
GROUP = "overly-permissive"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_CREATE_TIMEOUT_S = 1500.0
_DELETE_TIMEOUT_S = 1500.0
_ROLE_PROPAGATION_TIMEOUT_S = 60.0
_ROLE_PROPAGATION_INTERVAL_S = 5.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a 'creating' cluster fails with InvalidClusterStateFault "Node <name>-a is not in a
    valid state to be deleted." and the cluster keeps provisioning; once 'available', the same call deletes it."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _dax_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    # DeleteCluster is issued straight after CreateCluster returns: provisioning a DAX node
    # takes minutes, and a cluster that had already become available would accept the delete,
    # which _expect_error raises on.
    _create_cluster_retrying_role_propagation(
        dax,
        ClusterName=cluster_name,
        NodeType=_NODE_TYPE,
        ReplicationFactor=1,
        IamRoleArn=role_arn,
        SubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))

    creating = _describe_cluster(ctx, cluster_name)
    assert creating["Status"] == "creating", (
        f"cluster left the 'creating' state before the delete-while-creating probe "
        f"could run (observed status={creating['Status']!r})"
    )

    code, message = _expect_error(lambda: dax.delete_cluster(ClusterName=cluster_name))
    assert code == "InvalidClusterStateFault", (
        f"expected DeleteCluster on a still-creating cluster to be rejected with "
        f"InvalidClusterStateFault, got code={code!r}"
    )
    # DAX names a ReplicationFactor=1 cluster's only node "<cluster>-a".
    assert message == f"Node {cluster_name}-a is not in a valid state to be deleted.", message

    # Effect absent: the cluster is still there, provisioning or available, and
    # the rejected delete leaves it to finish provisioning.
    still_there = _cluster_status(ctx, cluster_name)
    assert still_there in ("creating", "available"), (
        f"expected the cluster to still be provisioning or available after the rejected "
        f"delete, got status={still_there!r}"
    )
    settled = _poll_until(
        lambda: _cluster_status(ctx, cluster_name),
        lambda status: status not in _TRANSIENT_STATUSES,
        timeout_s=_CREATE_TIMEOUT_S,
    )
    assert settled == "available", f"expected the cluster to settle at 'available', got {settled!r}"

    # Positive control: the same delete succeeds once the cluster is available.
    dax.delete_cluster(ClusterName=cluster_name)
    _poll_until(
        lambda: _cluster_status(ctx, cluster_name),
        lambda status: status == _GONE,
        timeout_s=_DELETE_TIMEOUT_S,
    )


_GONE = "<gone>"
_TRANSIENT_STATUSES = {"creating", "modifying"}


def _cluster_status(ctx, cluster_name):
    """The cluster's Status, or _GONE once DescribeClusters answers ClusterNotFoundFault."""
    try:
        return _describe_cluster(ctx, cluster_name)["Status"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ClusterNotFoundFault":
            return _GONE
        raise


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_cluster_retrying_role_propagation(dax, **kwargs):
    """DAX validates IamRoleArn at CreateCluster time; a role created moments ago may not yet be
    visible to DAX's control plane, which surfaces that as InvalidParameterValueException. Retry
    that one named error on a bounded deadline; anything else propagates immediately."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return dax.create_cluster(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(_ROLE_PROPAGATION_INTERVAL_S)


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


def _dax_subnet_ids(ctx, count=2):
    """Subnet ids for the DAX subnet group, in a VPC this check creates and removes."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.96.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dax-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zones = ec2.describe_availability_zones(
        Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
        ]
    )["AvailabilityZones"]
    names = sorted(z["ZoneName"] for z in zones)
    if len(names) < count:
        raise AssertionError(f"fewer than {count} usable availability zones in {ec2.meta.region_name!r}")
    subnet_ids = []
    for i, az in enumerate(names[:count], start=1):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.96.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_retrying_dependency(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _delete_retrying_dependency(fn, timeout_s=900.0, interval_s=15.0):
    """DAX releases its ENIs some minutes after the cluster is gone; retry DependencyViolation."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_subnet_group(ctx, subnet_ids):
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))
    return name


def _safe_delete_subnet_group(ctx, name):
    try:
        ctx.client("dax").delete_subnet_group(SubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ServiceLinkedRoleNotFoundFault",
            "SubnetGroupNotFoundFault",
        ):
            raise


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
    # No unconditional sleep here: role-propagation lag is bounded and retried where it actually
    # bites -- around the CreateCluster call itself, in _create_cluster_retrying_role_propagation.
    return role["Arn"]


def _safe_delete_cluster(ctx, cluster_name, timeout_s=_DELETE_TIMEOUT_S):
    dax = ctx.client("dax")
    if _cluster_status(ctx, cluster_name) == _GONE:
        return
    _poll_until(
        lambda: _cluster_status(ctx, cluster_name),
        lambda status: status not in _TRANSIENT_STATUSES,
        timeout_s=timeout_s,
    )
    try:
        dax.delete_cluster(ClusterName=cluster_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ClusterNotFoundFault":
            raise
    _poll_until(
        lambda: _cluster_status(ctx, cluster_name),
        lambda status: status == _GONE,
        timeout_s=timeout_s,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
