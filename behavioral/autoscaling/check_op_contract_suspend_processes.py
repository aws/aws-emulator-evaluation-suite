"""op-contract-suspend-processes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-suspend-processes"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SuspendProcesses adds exactly the named processes to SuspendedProcesses, and omitting
    ScalingProcesses suspends every process; an unrecognized process name is rejected and
    SuspendedProcesses is left untouched."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-suspendproc-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=2, desired=0)

    fresh = _suspended_names(autoscaling, name)
    assert fresh == set(), f"a freshly created ASG must have no suspended processes, got {fresh}"

    autoscaling.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["Launch", "HealthCheck"])
    named = _suspended_names(autoscaling, name)
    assert named == {"Launch", "HealthCheck"}, f"expected exactly Launch+HealthCheck suspended, got {named}"

    autoscaling.resume_processes(AutoScalingGroupName=name)
    resumed = _suspended_names(autoscaling, name)
    assert resumed == set(), f"resume_processes must clear SuspendedProcesses, got {resumed}"

    # Omitting ScalingProcesses suspends every known scaling process. Real AWS also suspends
    # some internal process types (e.g. "RemoveFromLoadBalancerLowPriority") that are not
    # enumerated by DescribeScalingProcessTypes, so the resulting SuspendedProcesses set can be
    # a strict superset of the documented process names -- assert the documented names are all
    # present rather than requiring an exact set match.
    all_process_names = {
        p["ProcessName"] for p in autoscaling.describe_scaling_process_types()["Processes"]
    }
    autoscaling.suspend_processes(AutoScalingGroupName=name)
    ctx.on_cleanup(lambda: autoscaling.resume_processes(AutoScalingGroupName=name))
    # DescribeAutoScalingGroups can lag briefly behind a blanket suspend of every process, so
    # poll for convergence instead of asserting on the very first read.
    suspended_all = _poll_until(
        lambda: _suspended_names(autoscaling, name),
        lambda names: all_process_names <= names,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert all_process_names <= suspended_all, (
        f"expected every documented process to be suspended, got {suspended_all}"
    )

    # Error boundary: an unrecognized process name is rejected, and the (already-full)
    # SuspendedProcesses set is unaffected by the rejected call.
    before = _suspended_names(autoscaling, name)
    code, message = _error(
        lambda: autoscaling.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["NotARealProcess"])
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = (
        "Request contained illegal suspendable process names: [NotARealProcess].Valid names are "
        ":[AZRebalance, AddToLoadBalancer, AlarmNotification, HealthCheck, InstanceRefresh, Launch, "
        "ReplaceUnhealthy, ScheduledActions, Terminate]."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after = _suspended_names(autoscaling, name)
    assert after == before, f"rejected SuspendProcesses call must not change SuspendedProcesses: {before} -> {after}"


def _suspended_names(autoscaling, name: str) -> set[str]:
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    return {p["ProcessName"] for p in group["SuspendedProcesses"]}


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _resolve_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, subnet_id: str, min_size: int, max_size: int, desired: int) -> None:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
