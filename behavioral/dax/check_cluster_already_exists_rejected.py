"""cluster-already-exists-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-already-exists-rejected"
GROUP = "overly-permissive"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_CREATE_TIMEOUT_S = 1500.0
_DELETE_TIMEOUT_S = 1500.0
_ROLE_PROPAGATION_TIMEOUT_S = 120.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster with a ClusterName that is already provisioning is rejected with
    ClusterAlreadyExistsFault, leaves the original cluster's NodeType unchanged, and the
    original create still reaches 'available'."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    original = _create_cluster_with_role_propagation_retry(
        dax,
        ClusterName=cluster_name,
        NodeType=_NODE_TYPE,
        ReplicationFactor=1,
        IamRoleArn=role_arn,
        SubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Cluster"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))

    code, message = _expect_rejected(
        lambda: dax.create_cluster(
            ClusterName=cluster_name,
            NodeType=_NODE_TYPE,
            ReplicationFactor=1,
            IamRoleArn=role_arn,
            SubnetGroupName=subnet_group_name,
        )
    )
    assert code == "ClusterAlreadyExistsFault", f"unexpected code: {code!r}"
    assert message == "Cluster with specified name already exists.", f"unexpected message: {message!r}"

    # Effect absent: exactly one cluster under this name, unchanged NodeType.
    matches = dax.describe_clusters(ClusterNames=[cluster_name])["Clusters"]
    assert len(matches) == 1
    assert matches[0]["NodeType"] == original["NodeType"]

    # Positive control: the original create is allowed to reach 'available'.
    available = _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["Status"] == "available",
        timeout_s=_CREATE_TIMEOUT_S,
    )
    assert available["ClusterName"] == cluster_name


# ===== helpers =====
def _cluster_gone(dax, cluster_name):
    """Cleanup-only existence probe: True once DescribeClusters reports ClusterNotFoundFault."""
    try:
        dax.describe_clusters(ClusterNames=[cluster_name])
    except ClientError as err:
        return err.response["Error"]["Code"] == "ClusterNotFoundFault"
    return False


def _expect_rejected(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting the duplicate create is the strongest signal
    available and must not be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ClusterAlreadyExistsFault, but the duplicate create_cluster SUCCEEDED: {result!r}")


def _create_cluster_with_role_propagation_retry(dax, timeout_s=_ROLE_PROPAGATION_TIMEOUT_S, **kwargs):
    """A freshly-created IAM role can take a few seconds to propagate before DAX can
    assume it; retry the bounded window instead of sleeping blind before the first try."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return dax.create_cluster(**kwargs)
        except dax.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)


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


def _default_vpc_subnet_ids(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for DAX subnet group creation")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"shared network has fewer than {count} subnets available")
    return [s["SubnetId"] for s in subnets[:count]]


def _create_subnet_group(ctx, subnet_ids):
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))
    return name


def _safe_delete_subnet_group(ctx, name, deadline_s=600.0, interval_s=2.0):
    # The cluster deletes asynchronously (several minutes) and holds the group
    # (SubnetGroupInUseFault) until it is gone.
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _safe_delete_cluster(ctx, cluster_name, timeout_s=_DELETE_TIMEOUT_S):
    dax = ctx.client("dax")
    if _cluster_gone(dax, cluster_name):
        return
    try:
        _poll_until(
            lambda: _describe_cluster(ctx, cluster_name),
            lambda c: c["Status"] == "available",
            timeout_s=timeout_s,
        )
    except AssertionError:
        pass
    try:
        dax.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
