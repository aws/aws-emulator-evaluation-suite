"""batch-add-cluster-nodes-limit-exceeded-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-add-cluster-nodes-limit-exceeded-blocked"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes summing past the instance quota (30 + 30) fails with ResourceLimitExceeded
    and the exact quota message, while a request naming a missing instance group returns 200 with
    one per-entry InstanceGroupNotFound failure and its exact message; TargetCount never moves."""
    sm = ctx.client("sagemaker")
    role_arn = _create_execution_role(ctx)
    subnet_ids, sg_id = _default_vpc_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    real_group = "controller"
    # Retry, not sleep, absorbs IAM propagation delay for the role just created above.
    _call_with_role_propagation_retry(
        lambda: sm.create_cluster(
            ClusterName=cluster_name,
            InstanceGroups=[
                {
                    "InstanceGroupName": real_group,
                    "InstanceType": "ml.c5.xlarge",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                }
            ],
            VpcConfig={"SecurityGroupIds": [sg_id], "Subnets": subnet_ids},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(sm, cluster_name))
    status = _wait_cluster_status(sm, cluster_name, {"InService", "Failed"}, timeout_s=1200)
    assert status == "InService", f"cluster never reached InService, ended at {status!r}"
    before_target = _target_count(sm, cluster_name, real_group)

    # break exactly one thing: two wire-valid entries (each <= 50) whose sum asks for more
    # instances than the account's HyperPod quota allows.
    over_limit_nodes = [
        {"InstanceGroupName": real_group, "IncrementTargetCountBy": 30},
        {"InstanceGroupName": real_group, "IncrementTargetCountBy": 30},
    ]
    usage_before = _cluster_instance_usage(sm)
    code, message = _error(
        lambda: sm.batch_add_cluster_nodes(ClusterName=cluster_name, NodesToAdd=over_limit_nodes)
    )
    usage_after = _cluster_instance_usage(sm)
    assert code == "ResourceLimitExceeded", (
        f"a NodesToAdd sum of 60 (30+30) past the account quota should be rejected with "
        f"ResourceLimitExceeded, got {code!r}"
    )
    # The message names the applied HyperPod instance quota and the instances the account's clusters
    # hold; utilization is read right before and after the call, and the message must match one.
    quota = _hyperpod_instance_quota(ctx)
    expected = {
        "The account-level service limit 'Total number of instances allowed across SageMaker Clusters' "
        f"is {quota} Instances, with current utilization of "
        f"{usage} Instances and a request delta of 60 Instances. "
        "Please use AWS Service Quotas to request an increase for this quota. "
        "If AWS Service Quotas is not available, contact AWS support to request an increase for this quota."
        for usage in (usage_before, usage_after)
    }
    assert message in expected, f"expected one of {sorted(expected)!r}, got {message!r}"

    # effect absent: the rejected request did not move the real group's target
    after_target = _target_count(sm, cluster_name, real_group)
    assert after_target == before_target, (
        f"the rejected over-quota request moved TargetCount {before_target} -> {after_target}"
    )

    # positive control: a within-quota request against the SAME cluster is processed (HTTP
    # 200, no exception); a nonexistent instance group shows up as a per-entry failure in
    # the response body, not a blanket reject
    missing_group = "sim2real-grp-a"
    resp = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name, NodesToAdd=[{"InstanceGroupName": missing_group, "IncrementTargetCountBy": 1}]
    )
    assert resp.get("Successful", []) == [], (
        f"a request targeting a nonexistent instance group should add nothing, got "
        f"Successful={resp.get('Successful')!r}"
    )
    failed = resp.get("Failed", [])
    assert len(failed) == 1, f"expected exactly one per-entry failure, got {failed!r}"
    assert failed[0]["ErrorCode"] == "InstanceGroupNotFound", (
        f"expected InstanceGroupNotFound for the missing group, got {failed[0]!r}"
    )
    expected_entry = (
        f"Instance group provided as part of the request ({missing_group}) does not exist. "
        "Please check the input and try again."
    )
    assert failed[0]["Message"] == expected_entry, (
        f"expected per-entry message {expected_entry!r}, got {failed[0]['Message']!r}"
    )
    assert failed[0]["InstanceGroupName"] == missing_group, (
        f"the per-entry failure named the wrong instance group: {failed[0]!r}"
    )
    assert failed[0]["FailedCount"] == 1, f"expected FailedCount 1, got {failed[0]!r}"

    # terminal read: independent of BatchAddClusterNodes' own response envelope -- the real
    # group's target is still where it started.
    final_target = _target_count(sm, cluster_name, real_group)
    assert final_target == before_target, (
        f"TargetCount moved after requests that added nothing: {before_target} -> {final_target}"
    )


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "batch-add-cluster-nodes-limit-exceeded-blocked"}],
    )
    role_arn = role["Role"]["Arn"]
    # on_cleanup runs LIFO: register delete_role first so it runs LAST, after the
    # detach below has already removed the attached policy (AWS refuses to delete a
    # role that still has a managed policy attached).
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _call_with_role_propagation_retry(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _wait_cluster_status(sm, cluster_name, terminal_statuses, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(2)
    raise AssertionError(f"cluster did not reach {terminal_statuses} within {timeout_s}s (last={status!r})")


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected this BatchAddClusterNodes call to be rejected, but it succeeded and "
        f"returned {result!r}"
    )


def _target_count(sm, cluster_name, group_name):
    described = sm.describe_cluster(ClusterName=cluster_name)
    group = next(g for g in described["InstanceGroups"] if g["InstanceGroupName"] == group_name)
    return group["TargetCount"]


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


def _hyperpod_instance_quota(ctx):
    """Applied value of "Total number of instances allowed across SageMaker HyperPod clusters"."""
    quota = ctx.client("service-quotas").get_service_quota(ServiceCode="sagemaker", QuotaCode="L-3308CCC7")
    return int(quota["Quota"]["Value"])


def _cluster_instance_usage(sm):
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
