"""batch-add-cluster-nodes-limit-exceeded-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-add-cluster-nodes-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes asking for 50 nodes past the instance quota fails with
    ResourceLimitExceeded and the exact message and leaves TargetCount unchanged, while a +1 on the
    same Slurm instance group is accepted."""
    sm = ctx.client("sagemaker")
    role_arn = _ensure_execution_role(ctx)
    vpc_id, subnet_ids, sg_id = _default_vpc_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    group_name = "controller"
    # A Slurm-orchestrated cluster (the default) rejects InstanceGroups unless one is a Controller
    # group with SlurmConfig; the accepted NodeType enum (Login/Compute/Controller) differs from the
    # model's Login/Worker/Controller.
    _create_cluster_with_role_propagation_retry(
        sm,
        ClusterName=cluster_name,
        InstanceGroups=[
            {
                "InstanceGroupName": group_name,
                "InstanceType": "ml.c5.xlarge",
                "InstanceCount": 1,
                "ExecutionRole": role_arn,
                "SlurmConfig": {"NodeType": "Controller"},
            },
        ],
        VpcConfig={"SecurityGroupIds": [sg_id], "Subnets": subnet_ids},
        Tags=[{"Key": "Name", "Value": cluster_name}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(sm, cluster_name))
    # Positive control: the cluster reaches a real InService state, so the eventual refusal
    # below cannot be explained by a globally broken or fully-denied account.
    _wait_cluster_status(ctx, cluster_name, {"InService", "Failed"}, timeout_s=1200)
    status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
    assert status == "InService", f"cluster never reached InService, ended at {status}"

    before_target = _target_count(sm, cluster_name, group_name)

    code, message = _error(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=cluster_name,
            NodesToAdd=[{"InstanceGroupName": group_name, "IncrementTargetCountBy": 50}],
        )
    )
    assert code == "ResourceLimitExceeded", f"expected ResourceLimitExceeded, got {code!r}"
    # The quota and utilization numbers are read from the message; they must say what the
    # refusal means: this cluster's instance is counted, and the delta pushes past the quota.
    numbers = re.fullmatch(
        r"The account-level service limit '.*' is (\d+) Instances, with current utilization of (\d+) Instances.*",
        message,
    )
    quota, usage = (int(n) for n in numbers.groups()) if numbers else (None, None)
    # message varies: the account's HyperPod instance quota and the instances every cluster in
    # the account holds right now; every other character is graded exactly.
    expected = (
        "The account-level service limit 'Total number of instances allowed across SageMaker Clusters' "
        f"is {quota} Instances, with current utilization of {usage} Instances and a request delta of "
        "50 Instances. Please use AWS Service Quotas to request an increase for this quota. "
        "If AWS Service Quotas is not available, contact AWS support to request an increase for this quota."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert usage >= 1, f"the utilization must count this check's own InService instance, got {usage}"
    assert usage + 50 > quota, f"a refused delta of 50 must exceed the quota: {usage} + 50 <= {quota}"

    # Effect absent: the rejected request did not move the group's target.
    after_reject = _target_count(sm, cluster_name, group_name)
    assert after_reject == before_target, (
        f"expected TargetCount unchanged by the rejected call, {before_target} -> {after_reject}"
    )

    # Positive control: a modest, in-quota increment on the same group is accepted.
    accepted = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": group_name, "IncrementTargetCountBy": 1}],
    )
    assert accepted["Failed"] == [], f"expected the modest add to succeed, got {accepted['Failed']!r}"
    groups = [n["InstanceGroupName"] for n in accepted["Successful"]]
    assert groups == [group_name], f"expected exactly one accepted node in {group_name!r}, got {groups!r}"


def _target_count(sm, cluster_name, group_name):
    described = sm.describe_cluster(ClusterName=cluster_name)
    group = next(g for g in described["InstanceGroups"] if g["InstanceGroupName"] == group_name)
    return group["TargetCount"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_cluster_and_wait(sm, cluster_name, timeout_s=600.0, interval_s=15.0):
    """Delete the cluster and wait until it is gone: HyperPod tears down the cluster's ENIs in
    the VPC with the execution role, so the role must outlive the deletion."""
    from botocore.exceptions import ClientError

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


def _create_cluster_with_role_propagation_retry(sm, timeout_s=90.0, interval_s=5.0, **kwargs):
    """CreateCluster validates the freshly-created execution role's trust policy, which is
    subject to IAM's own eventual consistency. Retry only while the failure names the role,
    bounded by a deadline, instead of an unconditional sleep before the first attempt."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_cluster(**kwargs)
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ensure_execution_role(ctx):
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
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _default_vpc_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets[:2]] or [subnets[0]["SubnetId"]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _wait_cluster_status(ctx, cluster_name, terminal_statuses, timeout_s):
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(2)
    raise AssertionError(f"cluster did not reach {terminal_statuses} within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
