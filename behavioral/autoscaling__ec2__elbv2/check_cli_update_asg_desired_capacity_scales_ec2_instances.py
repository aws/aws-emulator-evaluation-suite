"""cli-update-asg-desired-capacity-scales-ec2-instances."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-update-asg-desired-capacity-scales-ec2-instances"
GROUP = "cli-workflow"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """update-auto-scaling-group --desired-capacity drives real EC2 launch/terminate activity:
    scaling 1 -> 3 -> 1 must be observed as InService instance count transitions, not just a
    changed DesiredCapacity field."""
    require_tools("aws")

    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-asgscale-")
    sg_id = _create_security_group(ctx, vpc_id, name + "-sg")
    lt_id = _create_launch_template(ctx, name + "-lt", sg_id)
    asg_name = name + "-asg"

    _run_aws(
        ctx,
        "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", f"LaunchTemplateId={lt_id},Version=$Latest",
        "--min-size", "1", "--max-size", "5", "--desired-capacity", "1",
        "--vpc-zone-identifier", ",".join(subnet_ids),
    )
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, asg_name))

    ids_at_1 = _wait_for_instances_in_service(ctx, asg_name, 1, timeout_s=300.0)
    assert len(ids_at_1) == 1, f"expected 1 InService instance, got {ids_at_1}"

    ec2 = ctx.client("ec2")
    _assert_ec2_states(ctx, ec2, ids_at_1, {"running"}, timeout_s=60.0)

    _run_aws(
        ctx,
        "autoscaling", "update-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--desired-capacity", "3",
    )
    ids_at_3 = _wait_for_instances_in_service(ctx, asg_name, 3, timeout_s=300.0)
    assert len(ids_at_3) == 3, f"expected 3 InService instances after scale-out, got {ids_at_3}"
    assert set(ids_at_1).issubset(set(ids_at_3)), "original instance was replaced instead of scaled out"

    # ASG's own Instances list is the ASG's bookkeeping, not proof that EC2 itself launched
    # real instances -- a target that only updates the group's tracked membership without
    # ever calling RunInstances would still satisfy the assertions above. Read EC2 directly.
    _assert_ec2_states(ctx, ec2, ids_at_3, {"running"}, timeout_s=60.0)

    _run_aws(
        ctx,
        "autoscaling", "update-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--desired-capacity", "1",
    )
    final_ids = _wait_for_exact_instance_count(ctx, asg_name, 1, timeout_s=300.0)
    assert len(final_ids) == 1, f"expected exactly 1 instance after scale-in, got {final_ids}"

    terminated_ids = set(ids_at_3) - set(final_ids)
    assert len(terminated_ids) == 2, f"expected 2 instances removed by scale-in, got {terminated_ids}"
    # Likewise: prove the removed instances were actually terminated at EC2, at the
    # destination, not merely dropped from the ASG's own Instances bookkeeping.
    _wait_for_ec2_states(ctx, ec2, terminated_ids, {"shutting-down", "terminated"}, timeout_s=180.0)


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _get_default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; cannot discover subnets to provision "
            "ASG test infrastructure"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets; cannot provision ASG test infrastructure")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    return vpc_id, subnet_ids


def _create_security_group(ctx, vpc_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test security group",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = resp["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _create_launch_template(ctx, name: str, sg_id: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": "resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            "InstanceType": "t3.micro",
            "SecurityGroupIds": [sg_id],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        },
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _terminate_asg_and_wait(ctx, asg_name: str, timeout_s: float = 240.0) -> None:
    """Force-delete the group and wait until it is gone: a refusal while a scaling activity runs
    is retried every 2 s, a group already gone is done, anything else raises."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            busy = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")
            if err["Code"] not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"auto scaling group {asg_name} still listed at the teardown deadline")
        time.sleep(2)


def _wait_for_instances_in_service(ctx, asg_name: str, expected_count: int, timeout_s: float = 300.0):
    autoscaling = ctx.client("autoscaling")

    def probe():
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return []
        return [i["InstanceId"] for i in groups[0]["Instances"] if i["LifecycleState"] == "InService"]

    return _poll_until(probe, lambda ids: len(ids) >= expected_count, timeout_s=timeout_s, interval_s=10.0)


def _ec2_states(ec2, instance_ids):
    resp = ec2.describe_instances(InstanceIds=list(instance_ids))
    return {i["InstanceId"]: i["State"]["Name"] for r in resp["Reservations"] for i in r["Instances"]}


def _assert_ec2_states(ctx, ec2, instance_ids, allowed_states, *, timeout_s: float = 60.0):
    states = _poll_until(
        lambda: _ec2_states(ec2, instance_ids),
        lambda states: set(states.keys()) == set(instance_ids) and all(s in allowed_states for s in states.values()),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert set(states.keys()) == set(instance_ids), f"EC2 does not know all ASG-tracked instances: {states}"
    assert all(s in allowed_states for s in states.values()), (
        f"expected EC2 instance states in {allowed_states}, got {states}"
    )


def _wait_for_ec2_states(ctx, ec2, instance_ids, allowed_states, *, timeout_s: float = 180.0):
    states = _poll_until(
        lambda: _ec2_states(ec2, instance_ids),
        lambda states: all(s in allowed_states for s in states.values()),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    assert all(s in allowed_states for s in states.values()), (
        f"expected EC2 to have terminated {instance_ids}, but observed {states}"
    )
    return states


def _wait_for_exact_instance_count(ctx, asg_name: str, expected_count: int, timeout_s: float = 300.0):
    autoscaling = ctx.client("autoscaling")

    def probe():
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return []
        return [i["InstanceId"] for i in groups[0]["Instances"]]

    return _poll_until(probe, lambda ids: len(ids) == expected_count, timeout_s=timeout_s, interval_s=10.0)



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
