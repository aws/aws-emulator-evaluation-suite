"""attach-cluster-node-volume-unknown-node-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-cluster-node-volume-unknown-node-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

NODE_NOT_FOUND = "Specified cluster node not found"
SLURM_REFUSAL = "Volume operations are not supported for Slurm clusters"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachClusterNodeVolume with an unknown NodeId on a real cluster is ResourceNotFound and
    attaches nothing; the cluster's real node passes the node lookup and is refused only for the
    Slurm orchestrator (ValidationException), and the volume keeps no attachment either way.
    """
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")
    cluster_name = _provision_slurm_cluster(ctx, "controller")
    cluster_arn = sm.describe_cluster(ClusterName=cluster_name)["ClusterArn"]

    nodes = sm.list_cluster_nodes(ClusterName=cluster_name)["ClusterNodeSummaries"]
    assert len(nodes) == 1, f"expected the one Controller node, got {nodes!r}"
    node_id = nodes[0]["InstanceId"]
    # HyperPod nodes are not instances in the caller's EC2 account, so the AZ comes from
    # DescribeClusterNode rather than ec2:DescribeInstances.
    az = sm.describe_cluster_node(ClusterName=cluster_name, NodeId=node_id)["NodeDetails"]["Placement"][
        "AvailabilityZone"
    ]

    # AttachClusterNodeVolume validates the VolumeId against EC2 before the NodeId, so the
    # volume is real and only the NodeId is unknown.
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))
    _wait_volume_available(ctx, ec2, volume_id)

    # --- negative: a syntactically valid NodeId that does not exist on the real cluster ---
    bogus_node_id = "i-00000000"
    assert bogus_node_id != node_id
    code, message = _error(
        lambda: sm.attach_cluster_node_volume(ClusterArn=cluster_arn, NodeId=bogus_node_id, VolumeId=volume_id)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}: {message!r}"
    assert message == NODE_NOT_FOUND, f"expected message {NODE_NOT_FOUND!r}, got {message!r}"

    # effect absent: the volume was not attached to anything
    state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
    assert state == "available", f"volume {volume_id} should remain available, got {state!r}"

    # --- control: the real node passes the node lookup and meets the orchestrator check ---
    code, message = _error(
        lambda: sm.attach_cluster_node_volume(ClusterArn=cluster_arn, NodeId=node_id, VolumeId=volume_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == SLURM_REFUSAL, f"expected message {SLURM_REFUSAL!r}, got {message!r}"
    assert message != NODE_NOT_FOUND, "a real node and an unknown node must not collapse to one answer"
    described = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert described["State"] == "available", f"volume {volume_id} should remain available, got {described['State']!r}"
    assert described["Attachments"] == [], f"volume {volume_id} gained an attachment: {described['Attachments']!r}"


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_volume(ec2, volume_id: str) -> None:
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


def _provision_slurm_cluster(ctx, group_name: str) -> str:
    """The smallest real cluster CreateCluster accepts: one Slurm Controller instance group in
    the default VPC (or a VPC the check creates), waited to InService."""
    sm = ctx.client("sagemaker")
    role_arn = _create_role(ctx)
    subnet_ids, sg_id = _default_vpc_network(ctx)
    cluster_name = ctx.unique_name("sim2real-sm-cl-")

    def _create():
        return sm.create_cluster(
            ClusterName=cluster_name,
            InstanceGroups=[
                {
                    "InstanceGroupName": group_name,
                    "InstanceType": "ml.c5.xlarge",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                }
            ],
            VpcConfig={"SecurityGroupIds": [sg_id], "Subnets": subnet_ids},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _cleanup_cluster(ctx, cluster_name))
    _wait_cluster_status(ctx, cluster_name, "InService", timeout_s=1200)
    return cluster_name


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    # Teardowns run LIFO: the delete is registered first so the policy detach runs before it.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _default_vpc_network(ctx: Any) -> tuple[list[str], str]:
    """Two subnets and the default security group of the shared network; an account without a
    shared network gets a VPC with two subnets that this check creates and deletes."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnet_ids = [
            s["SubnetId"]
            for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        ][:2]
    else:
        vpc_id, subnet_ids = _create_vpc_with_subnets(ctx, ec2)
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_ids, sg_id


def _create_vpc_with_subnets(ctx: Any, ec2: Any) -> tuple[str, list[str]]:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.195.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.195.{i}.0/24",
            AvailabilityZone=azs[i % len(azs)]["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _delete_retrying(fn, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    """Retry a network delete while HyperPod's ENIs leave the subnet (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_volume_available(ctx: Any, ec2, volume_id: str, timeout_s: float = 600.0) -> None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        if state == "available":
            return
        if state in ("deleted", "error"):
            raise AssertionError(f"EBS volume {volume_id} entered {state!r} instead of available")
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"EBS volume {volume_id} to become available: the run budget ended first; not graded")
            raise AssertionError(
                f"EBS volume {volume_id} was not available within {timeout_s:.0f}s; last state {state!r}"
            )
        time.sleep(1.0)


def _wait_cluster_status(ctx: Any, cluster_name: str, want: str, timeout_s: float, interval_s: float = 2.0) -> None:
    sm = ctx.client("sagemaker")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        described = sm.describe_cluster(ClusterName=cluster_name)
        if described["ClusterStatus"] == want:
            return
        if described["ClusterStatus"] == "Failed":
            raise AssertionError(f"HyperPod cluster entered Failed: {described.get('FailureMessage')!r}")
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"HyperPod cluster to reach {want}: the run budget ended first; not graded")
            raise AssertionError(
                f"HyperPod cluster did not reach {want} within {timeout_s:.0f}s; "
                f"last status {described['ClusterStatus']!r}"
            )
        time.sleep(interval_s)


def _cleanup_cluster(ctx: Any, cluster_name: str) -> None:
    _delete_cluster_and_wait(ctx.client("sagemaker"), cluster_name)


def _delete_cluster_and_wait(sm, cluster_name, timeout_s=600.0, interval_s=15.0):
    """Delete the cluster and wait until it is gone: HyperPod tears down the cluster's ENIs in
    the VPC with the execution role, so the role must outlive the deletion."""
    try:
        sm.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
