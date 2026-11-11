"""decrease-replication-factor-invalid-node-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decrease-replication-factor-invalid-node-rejected"
GROUP = "overly-permissive"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_TIMEOUT_S = 1500.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DecreaseReplicationFactor naming node IDs not in the cluster fails with NodeNotFoundFault "Node not
    found." and leaves TotalNodes at 3, while removing the two real replica nodes shrinks the cluster to one."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    _create_cluster_when_role_ready(
        dax, cluster_name=cluster_name, role_arn=role_arn, subnet_group_name=subnet_group_name
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))
    grown = _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["Status"] == "available" and c["TotalNodes"] == 3,
        timeout_s=_TIMEOUT_S,
    )
    dax.tag_resource(
        ResourceName=grown["ClusterArn"], Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    replica_ids = [n["NodeId"] for n in grown["Nodes"][1:]]
    assert len(replica_ids) == 2, f"expected 2 replica nodes on a RF=3 cluster, got {replica_ids!r}"

    code, message = _expect_error(
        lambda: dax.decrease_replication_factor(
            ClusterName=cluster_name,
            NewReplicationFactor=1,
            NodeIdsToRemove=["sim2real-bogus-node-1", "sim2real-bogus-node-2"],
        )
    )
    assert code == "NodeNotFoundFault", f"expected NodeNotFoundFault, got {code!r}"
    assert message == "Node not found.", f"unexpected message: {message!r}"

    unchanged = _describe_cluster(ctx, cluster_name)
    assert unchanged["TotalNodes"] == 3, (
        f"rejected decrease must leave node count unchanged, got TotalNodes={unchanged['TotalNodes']!r}"
    )

    dax.decrease_replication_factor(
        ClusterName=cluster_name, NewReplicationFactor=1, NodeIdsToRemove=replica_ids
    )
    shrunk = _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["Status"] == "available" and c["TotalNodes"] == 1,
        timeout_s=_TIMEOUT_S,
    )
    assert len(shrunk["Nodes"]) == 1, f"expected the cluster to shrink to 1 node, got {shrunk['Nodes']!r}"


def _cluster_gone(dax, cluster_name):
    """Existence probe: True once DescribeClusters reports ClusterNotFoundFault."""
    try:
        dax.describe_clusters(ClusterNames=[cluster_name])
    except ClientError as err:
        return err.response["Error"]["Code"] == "ClusterNotFoundFault"
    return False


def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _describe_cluster(ctx, cluster_name):
    return ctx.client("dax").describe_clusters(ClusterNames=[cluster_name])["Clusters"][0]


def _create_cluster_when_role_ready(dax, *, cluster_name, role_arn, subnet_group_name, timeout_s=60.0):
    """CreateCluster validates IamRoleArn synchronously, and a role created moments ago may not
    yet be visible to that validation. Retry only on the role-related rejection, bounded, rather
    than sleeping blind before the first attempt."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return dax.create_cluster(
                ClusterName=cluster_name,
                NodeType=_NODE_TYPE,
                ReplicationFactor=3,
                IamRoleArn=role_arn,
                SubnetGroupName=subnet_group_name,
            )["Cluster"]
        except ClientError as err:
            error = err.response["Error"]
            if "role" not in error.get("Message", "").lower() or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


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
    return role["Arn"]


def _safe_delete_cluster(ctx, cluster_name, timeout_s=_TIMEOUT_S):
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
