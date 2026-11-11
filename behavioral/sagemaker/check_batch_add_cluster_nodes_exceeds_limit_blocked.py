"""batch-add-cluster-nodes-exceeds-limit-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-add-cluster-nodes-exceeds-limit-blocked"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """BatchAddClusterNodes beyond the HyperPod instance quota fails with ResourceLimitExceeded
    and adds no nodes, while a modest addition to the same group moves its TargetCount."""
    sm = ctx.client("sagemaker")
    group_name = "controller"
    cluster_name = _provision_slurm_cluster(ctx, group_name)

    before_nodes = len(
        sm.list_cluster_nodes(ClusterName=cluster_name).get("ClusterNodeSummaries", [])
    )

    # 50 nodes exceeds the HyperPod instance quota of any small test account.
    code, message = _error(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=cluster_name,
            NodesToAdd=[{"InstanceGroupName": group_name, "IncrementTargetCountBy": 50}],
        )
    )
    assert code == "ResourceLimitExceeded", f"expected ResourceLimitExceeded, got {code}"
    expected = _quota_message(ctx, sm, 50)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_nodes = len(
        sm.list_cluster_nodes(ClusterName=cluster_name).get("ClusterNodeSummaries", [])
    )
    assert after_nodes == before_nodes, (
        f"node count changed after a rejected BatchAddClusterNodes call: "
        f"{before_nodes} -> {after_nodes}"
    )

    before_target = _instance_group(sm, cluster_name, group_name)["TargetCount"]
    good_resp = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": group_name, "IncrementTargetCountBy": 1}],
    )
    assert len(good_resp["Successful"]) == 1
    assert good_resp["Failed"] == []

    # Independent read: the accepted request moved the group's target, not just its response.
    after_target = _instance_group(sm, cluster_name, group_name)["TargetCount"]
    assert after_target == before_target + 1, (
        f"accepted BatchAddClusterNodes did not raise the instance group's target count: "
        f"{before_target} -> {after_target}"
    )


def _instance_group(sm, cluster_name: str, group_name: str) -> dict:
    described = sm.describe_cluster(ClusterName=cluster_name)
    return next(
        g for g in described["InstanceGroups"] if g["InstanceGroupName"] == group_name
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
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


def _hyperpod_instance_quota(ctx: Any) -> int:
    """Applied value of "Total number of instances allowed across SageMaker HyperPod clusters"."""
    quota = ctx.client("service-quotas").get_service_quota(ServiceCode="sagemaker", QuotaCode="L-3308CCC7")
    return int(quota["Quota"]["Value"])


def _cluster_instance_usage(sm: Any) -> int:
    """Instances the account's live HyperPod clusters hold, summed over every instance group's
    CurrentCount; a Deleting cluster still reports its old count but no longer uses the quota."""
    total = 0
    for page in sm.get_paginator("list_clusters").paginate():
        for summary in page["ClusterSummaries"]:
            if summary["ClusterStatus"] in ("Deleting", "Failed"):
                continue
            described = sm.describe_cluster(ClusterName=summary["ClusterName"])
            total += sum(g["CurrentCount"] for g in described.get("InstanceGroups", []))
    return total


def _quota_message(ctx: Any, sm: Any, delta: int) -> str:
    """ResourceLimitExceeded's text: the applied quota and live utilization are read, not pinned."""
    return (
        "The account-level service limit 'Total number of instances allowed across SageMaker Clusters' "
        f"is {_hyperpod_instance_quota(ctx)} Instances, with current utilization of "
        f"{_cluster_instance_usage(sm)} Instances and a request delta of {delta} Instances. "
        "Please use AWS Service Quotas to request an increase for this quota. "
        "If AWS Service Quotas is not available, contact AWS support to request an increase for this quota."
    )


def _wait_cluster_status(ctx: Any, cluster_name: str, want: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = sm.describe_cluster(ClusterName=cluster_name)
        status = described["ClusterStatus"]
        if status == want:
            return
        if status == "Failed":
            raise AssertionError(
                f"HyperPod cluster entered Failed: {described.get('FailureMessage')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"HyperPod cluster did not reach {want} within {timeout_s}s")


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
