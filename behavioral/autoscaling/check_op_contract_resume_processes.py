"""op-contract-resume-processes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-resume-processes"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResumeProcesses removes exactly the named processes from SuspendedProcesses (partial
    resume), and omitting ScalingProcesses resumes everything; an unrecognized process name is
    rejected and SuspendedProcesses is left untouched."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _own_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-resumeproc-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=2, desired=0)

    autoscaling.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["AlarmNotification", "AZRebalance"])
    suspended = _suspended_names(autoscaling, name)
    assert suspended == {"AlarmNotification", "AZRebalance"}, (
        f"expected {{'AlarmNotification', 'AZRebalance'}} suspended after SuspendProcesses, got {suspended}"
    )

    # Partial resume: only AlarmNotification comes back into service.
    autoscaling.resume_processes(AutoScalingGroupName=name, ScalingProcesses=["AlarmNotification"])
    after_partial = _suspended_names(autoscaling, name)
    assert after_partial == {"AZRebalance"}, (
        f"expected only {{'AZRebalance'}} to remain suspended after a partial resume, got {after_partial}"
    )

    # Full resume: omitting ScalingProcesses resumes every remaining suspended process.
    autoscaling.resume_processes(AutoScalingGroupName=name)
    after_full = _suspended_names(autoscaling, name)
    assert after_full == set(), f"expected no processes suspended after a full resume, got {after_full}"

    # Error boundary: an unrecognized process name is rejected by ResumeProcesses and the
    # (already-empty) SuspendedProcesses list is unaffected by the rejected call.
    code, message = _error(
        lambda: autoscaling.resume_processes(AutoScalingGroupName=name, ScalingProcesses=["NotARealProcess"])
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = (
        "Request contained illegal suspendable process names: [NotARealProcess].Valid names are "
        ":[AZRebalance, AddToLoadBalancer, AlarmNotification, HealthCheck, InstanceRefresh, Launch, "
        "ReplaceUnhealthy, ScheduledActions, Terminate]."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after_rejected = _suspended_names(autoscaling, name)
    assert after_rejected == set(), (
        f"a rejected ResumeProcesses call must not change SuspendedProcesses, got {after_rejected}"
    )


def _suspended_names(autoscaling, name: str) -> set[str]:
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    return {p["ProcessName"] for p in group["SuspendedProcesses"]}


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises: accepting input
    real AWS refuses is a failure in its own right, not an error-code mismatch."""
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


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _own_subnet(ctx) -> str:
    """Subnet in a VPC this check creates and owns, rather than assuming the account already has
    a default VPC -- a freshly provisioned account may not."""
    ec2 = ctx.client("ec2")
    cidr = "10.201.0.0/24"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        description=f"vpc {vpc_id} becoming available",
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id


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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that would leak the
# VPC while the check passes. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
