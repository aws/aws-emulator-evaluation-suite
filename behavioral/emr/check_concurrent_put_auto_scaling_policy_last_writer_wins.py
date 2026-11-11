"""concurrent-put-auto-scaling-policy-last-writer-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-auto-scaling-policy-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutAutoScalingPolicy calls on the same instance group converge to a
    single, internally-consistent policy (no torn mix of one policy's rules with the other's
    constraints)."""
    auto_scaling_role = _own_role(
        ctx, "sim2real-emr-as-",
        ["elasticmapreduce.amazonaws.com", "application-autoscaling.amazonaws.com"],
        "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforAutoScalingRole",
    )
    cluster_id = _provision_cluster(ctx, release_label="emr-6.15.0", auto_scaling_role=auto_scaling_role)
    _wait_cluster_ready(ctx, cluster_id)

    emr = ctx.client("emr")
    groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
    core_group_id = next(g["Id"] for g in groups if g["InstanceGroupType"] == "CORE")

    def _policy(tag, max_capacity):
        return {
            "Constraints": {"MinCapacity": 1, "MaxCapacity": max_capacity},
            "Rules": [
                {
                    "Name": f"sim2real-{tag}",
                    "Description": tag,
                    "Action": {
                        "SimpleScalingPolicyConfiguration": {
                            "AdjustmentType": "CHANGE_IN_CAPACITY",
                            "ScalingAdjustment": 1,
                            "CoolDown": 300,
                        }
                    },
                    "Trigger": {
                        "CloudWatchAlarmDefinition": {
                            "ComparisonOperator": "LESS_THAN",
                            "MetricName": "YARNMemoryAvailablePercentage",
                            "Period": 300,
                            "Threshold": 15.0,
                        }
                    },
                }
            ],
        }

    policy_a = _policy("policy-a", 2)
    policy_b = _policy("policy-b", 3)

    def _put(policy):
        emr.put_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=core_group_id, AutoScalingPolicy=policy)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, policy_a), pool.submit(_put, policy_b)]
        for f in futures:
            f.result()

    final_groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
    final_group = next(g for g in final_groups if g["Id"] == core_group_id)
    final_rule_name = final_group["AutoScalingPolicy"]["Rules"][0]["Name"]
    final_max_capacity = final_group["AutoScalingPolicy"]["Constraints"]["MaxCapacity"]

    assert final_rule_name in ("sim2real-policy-a", "sim2real-policy-b"), (
        f"expected the converged policy to be one of the two submitted rule names, "
        f"got rule name {final_rule_name!r} in {final_group['AutoScalingPolicy']!r}"
    )
    if final_rule_name == "sim2real-policy-a":
        assert final_max_capacity == 2, (
            f"torn write: rule name is sim2real-policy-a (from policy_a) but MaxCapacity is "
            f"{final_max_capacity} instead of policy_a's own MaxCapacity=2"
        )
    else:
        assert final_max_capacity == 3, (
            f"torn write: rule name is sim2real-policy-b (from policy_b) but MaxCapacity is "
            f"{final_max_capacity} instead of policy_b's own MaxCapacity=3"
        )


def _own_role(ctx, prefix, service_principal, policy_arn):
    """A role of this check's own (not the account's shared EMR_*_DefaultRole), torn down at the end."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _iam_delete(iam.delete_role, RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _iam_delete(iam.detach_role_policy, RoleName=role_name, PolicyArn=policy_arn))
    return role_name


def _iam_delete(op, **kwargs):
    """An IAM teardown call; only an already-absent entity is tolerated."""
    try:
        op(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _own_emr_roles(ctx):
    """This check's own EMR service role and EC2 role with its instance profile."""
    iam = ctx.client("iam")
    service_role = _own_role(
        ctx, "sim2real-emr-svc-", "elasticmapreduce.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole",
    )
    ec2_role = _own_role(
        ctx, "sim2real-emr-ec2-", "ec2.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role",
    )
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    ctx.on_cleanup(lambda: _iam_delete(iam.delete_instance_profile, InstanceProfileName=ec2_role))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: _iam_delete(
        iam.remove_role_from_instance_profile, InstanceProfileName=ec2_role, RoleName=ec2_role
    ))
    return service_role, ec2_role


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch a test EMR cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available to launch a test EMR cluster")
    return subnets[0]["SubnetId"]


def _provision_cluster(ctx, *, release_label, session_enabled=False, use_fleets=False, applications=None, auto_scaling_role=None):
    emr = ctx.client("emr")
    service_role, ec2_role = _own_emr_roles(ctx)
    subnet_id = _default_subnet(ctx)
    master_sg, slave_sg = _own_emr_security_groups(ctx)
    if use_fleets:
        instances = {
            "Ec2SubnetId": subnet_id,
            "EmrManagedMasterSecurityGroup": master_sg,
            "EmrManagedSlaveSecurityGroup": slave_sg,
            "KeepJobFlowAliveWhenNoSteps": True,
            "InstanceFleets": [
                {"InstanceFleetType": "MASTER", "TargetOnDemandCapacity": 1,
                 "InstanceTypeConfigs": [{"InstanceType": "m5.xlarge"}]},
                {"InstanceFleetType": "CORE", "TargetOnDemandCapacity": 1,
                 "InstanceTypeConfigs": [{"InstanceType": "m5.xlarge"}]},
            ],
        }
    else:
        instances = {
            "Ec2SubnetId": subnet_id,
            "EmrManagedMasterSecurityGroup": master_sg,
            "EmrManagedSlaveSecurityGroup": slave_sg,
            "KeepJobFlowAliveWhenNoSteps": True,
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
        }
    kwargs = dict(
        Name=ctx.unique_name("sim2real-emr-cluster-"),
        ReleaseLabel=release_label,
        Applications=applications or [{"Name": "Hadoop"}],
        ServiceRole=service_role,
        JobFlowRole=ec2_role,
        VisibleToAllUsers=True,
        Instances=instances,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    if session_enabled:
        kwargs["SessionEnabled"] = True
    if auto_scaling_role:
        kwargs["AutoScalingRole"] = auto_scaling_role
    resp = _run_job_flow_awaiting_role_propagation(emr, kwargs)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(emr, cluster_id))
    return cluster_id


def _run_job_flow_awaiting_role_propagation(emr, kwargs, timeout_s=180.0, interval_s=10.0):
    """A role/instance-profile created moments ago by this same check may not yet be visible
    to EMR's control plane; bound the wait on that specific, named condition rather than
    guessing a fixed settle time."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as exc:
            error = exc.response["Error"]
            message = error.get("Message", "").lower()
            # e.g. "Invalid InstanceProfile: <name>." for a seconds-old instance profile.
            role_not_yet_visible = error["Code"] == "ValidationException" and (
                "role" in message or "instance profile" in message or "instanceprofile" in message
            )
            if not role_not_yet_visible or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_cluster_ready(ctx, cluster_id, timeout_s=1500.0, interval_s=20.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in ("RUNNING", "WAITING"):
            return state
        if state in ("TERMINATING", "TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster {cluster_id} entered {state} before becoming ready")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not become ready within {timeout_s}s")


def _own_emr_security_groups(ctx):
    """Two security groups of this check's own, passed to RunJobFlow as the cluster's
    the EMR-managed primary and core security groups (its Ec2InstanceAttributes).

    EMR then adds its rules to these instead of creating the VPC-wide ElasticMapReduce-* default
    groups other clusters in the run's shared network share, and the teardown deletes exactly
    these two once the cluster has terminated.
    """
    ec2 = ctx.client("ec2")
    group_ids = []
    ctx.on_cleanup(lambda: _delete_emr_security_groups(ec2, group_ids))
    for role in ("master", "slave"):
        group_ids.append(ec2.create_security_group(
            GroupName=ctx.unique_name(f"sim2real-emr-{role}-"),
            Description=f"sim2real EMR-managed {role} security group",
            VpcId=ctx.network().vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
        )["GroupId"])
    return group_ids[0], group_ids[1]


def _delete_emr_security_groups(ec2, group_ids, timeout_s=600.0, interval_s=15.0):
    """Revoke the rules EMR added between the two groups, then delete both; a group still held by
    the terminating cluster's network interfaces is retried until the deadline, then raised."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    remaining = list(group_ids)
    while remaining:
        try:
            groups = ec2.describe_security_groups(GroupIds=remaining)["SecurityGroups"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidGroup.NotFound":
                raise
            groups = [
                g for gid in remaining
                for g in _describe_group_or_none(ec2, gid)
            ]
        for group in groups:
            for key, revoke in (
                ("IpPermissions", ec2.revoke_security_group_ingress),
                ("IpPermissionsEgress", ec2.revoke_security_group_egress),
            ):
                refs = [perm for perm in group.get(key, []) if perm.get("UserIdGroupPairs")]
                if refs:
                    try:
                        revoke(GroupId=group["GroupId"], IpPermissions=refs)
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "InvalidPermission.NotFound":
                            raise
        pending = []
        for group in groups:
            try:
                ec2.delete_security_group(GroupId=group["GroupId"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    continue
                if code != "DependencyViolation":
                    raise
                pending.append(group["GroupId"])
        remaining = pending
        if remaining and time.monotonic() >= deadline:
            raise AssertionError(f"EMR security groups {remaining} still in use {timeout_s}s after teardown began")
        if remaining:
            time.sleep(interval_s)


def _describe_group_or_none(ec2, group_id):
    from botocore.exceptions import ClientError

    try:
        return ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            return []
        raise


def _terminate_and_wait(emr, cluster_id):
    """Terminate the cluster and wait until it is TERMINATED, so its instances' network interfaces
    leave its security groups before those are deleted."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    emr.get_waiter("cluster_terminated").wait(
        ClusterId=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 400}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
