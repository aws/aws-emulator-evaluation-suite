"""instance-refresh-serialized-then-cancelled."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-refresh-serialized-then-cancelled"
GROUP = 'instance-refresh'
SERVICES = ['autoscaling']

def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


_AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
# DescribeImages fallback when the execution role has no ssm:GetParameter.
_AMI_NAME_PATTERNS = (
    "al2023-ami-2023.*-kernel-6.1-x86_64",
    "al2023-ami-*-x86_64",
    "amzn2-ami-hvm-*-x86_64-gp2",
)
_CANDIDATE_INSTANCE_TYPES = ("t3.micro", "t2.micro", "t3a.micro")
# The tag the suite stamps on every resource it creates, so a leftover can be found by tag and
# find leftovers. It is also the "unrelated tag" a targeted DeleteTags must not touch.
_MANAGED_TAG_KEY = "sim2real:managed"


def _resolve_ami(ec2, ssm) -> str:
    """Resolve a real, bootable x86_64 Amazon Linux AMI id.

    Auto Scaling data-plane semantics (Pending -> InService -> Terminating, standby,
    refresh, health replacement) are only observable if instances actually launch, so a
    placeholder AMI id would make every state-machine assertion untestable. Prefers the
    public SSM alias (one cheap call), but the execution role may not hold
    ``ssm:GetParameter``, so fall back to EC2 DescribeImages over the Amazon-owned
    Amazon Linux families and take the newest.
    """
    errors: list[str] = []
    try:
        return ssm.get_parameter(Name=_AL2023_SSM_PARAM)["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001
        errors.append(f"ssm:{exc}")

    for name_pattern in _AMI_NAME_PATTERNS:
        try:
            images = ec2.describe_images(
                Owners=["amazon"],
                Filters=[
                    {"Name": "name", "Values": [name_pattern]},
                    {"Name": "state", "Values": ["available"]},
                    {"Name": "architecture", "Values": ["x86_64"]},
                    {"Name": "root-device-type", "Values": ["ebs"]},
                    {"Name": "virtualization-type", "Values": ["hvm"]},
                ],
            ).get("Images", [])
        except Exception as exc:  # noqa: BLE001
            errors.append(f"describe_images({name_pattern}):{exc}")
            continue
        if images:
            return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]
        errors.append(f"describe_images({name_pattern}):no images")

    raise AssertionError(f"could not resolve a bootable AMI id ({'; '.join(errors)})")


def _network(ctx, ec2) -> tuple[str, str, str]:
    """(subnet_id, instance_type, vpc_id) in a VPC and subnet this check creates."""
    resp = ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": list(_CANDIDATE_INSTANCE_TYPES)}],
    )
    offered = {o["InstanceType"] for o in resp.get("InstanceTypeOfferings", [])}
    for itype in _CANDIDATE_INSTANCE_TYPES:
        if itype in offered:
            vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ec2, instance_type=itype)
            return subnet_id, itype, vpc_id
    raise AssertionError(f"no candidate instance type is offered: {_CANDIDATE_INSTANCE_TYPES}")


def _discover_env(ctx):
    """One-shot AMI / subnet / instance-type discovery shared by every group this check builds."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    subnet_id, instance_type, _vpc_id = _network(ctx, ec2)
    return {
        "ec2": ec2,
        "ami": _resolve_ami(ec2, ssm),
        "subnet": subnet_id,
        "instance_type": instance_type,
    }


def _delete_launch_template(ec2, name) -> None:
    """Delete a launch template, retrying for 30 s while a still-draining group pins it.

    delete_auto_scaling_group(ForceDelete=True) returns before the group is actually
    gone; a refusal that outlasts the window raises.
    """
    deadline = time.monotonic() + 30
    while True:
        try:
            ec2.delete_launch_template(LaunchTemplateName=name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == (
                "InvalidLaunchTemplateName.NotFoundException"
            ):
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _make_launch_template(ctx, env) -> str:
    """Create an EC2 launch template usable by an Auto Scaling group."""
    name = ctx.unique_name("sim2real-behav-asg-lt-")
    env["ec2"].create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": env["ami"], "InstanceType": env["instance_type"]},
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
            }
        ],
    )
    ctx.on_cleanup(lambda: _delete_launch_template(env["ec2"], name))
    return name


def _make_group(
    ctx,
    as_,
    env,
    *,
    min_size: int = 0,
    max_size: int = 2,
    desired_capacity=None,
    launch_template=None,
    **overrides,
) -> str:
    """Create an Auto Scaling group (and, unless given one, its launch template)."""
    name = ctx.unique_name("sim2real-behav-asg-grp-")
    params: dict = {
        "AutoScalingGroupName": name,
        "MinSize": min_size,
        "MaxSize": max_size,
        "VPCZoneIdentifier": env["subnet"],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 0,
        "DefaultCooldown": 0,
        "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true", "PropagateAtLaunch": True}],
    }
    lt = launch_template or _make_launch_template(ctx, env)
    params["LaunchTemplate"] = {"LaunchTemplateName": lt, "Version": "$Latest"}
    if desired_capacity is not None:
        params["DesiredCapacity"] = desired_capacity
    params.update(overrides)
    as_.create_auto_scaling_group(**params)
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name


def _describe_group(as_, name):
    groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
        "AutoScalingGroups", []
    )
    return groups[0] if groups else None


def _group_instances(as_, name) -> list:
    grp = _describe_group(as_, name)
    return grp.get("Instances", []) if grp else []


def _in_service_ids(as_, name) -> list:
    return [
        i["InstanceId"]
        for i in _group_instances(as_, name)
        if i["LifecycleState"] == "InService"
    ]


def _wait_for_in_service(as_, name, count, timeout_s=180, interval_s=5) -> list:
    """Block until exactly *count* instances are InService; return their ids."""
    return _poll_until(
        lambda: _in_service_ids(as_, name),
        lambda ids: len(ids) == count,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"group {name} reaching {count} InService instance(s)",
    )


def _wait_for_membership_settled(as_, name, count, timeout_s=180, interval_s=5) -> list:
    """Block until the group has EXACTLY *count* instances, all InService.

    A cancelled instance refresh halts further steps but does not roll back a step
    already in flight, so a replacement instance can still be mid-launch (Pending) or
    mid-terminate (Terminating) right after CancelInstanceRefresh reports Cancelled.
    Force-deleting the group while that straggler is not yet a settled member risks it
    escaping the delete's terminate-everything sweep and being orphaned outside any
    group. Call this before it is safe to force-delete.
    """
    return _poll_until(
        lambda: _group_instances(as_, name),
        lambda ins: len(ins) == count
        and all(i["LifecycleState"] == "InService" for i in ins),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"group {name} settling to {count} InService instance(s) with no stragglers",
    )


def _refresh_record(as_, name, refresh_id):
    items = as_.describe_instance_refreshes(
        AutoScalingGroupName=name, InstanceRefreshIds=[refresh_id]
    ).get("InstanceRefreshes", [])
    return items[0] if items else None


def _wait_for_refresh_status(as_, name, refresh_id, statuses, timeout_s=240, interval_s=5):
    return _poll_until(
        lambda: (_refresh_record(as_, name, refresh_id) or {}).get("Status"),
        lambda s: s in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"refresh {refresh_id} reaching one of {sorted(map(str, statuses))}",
    )


def _cancel_if_active(as_, name) -> None:
    """Teardown: cancel a refresh the run left active; the run itself cancels on its own path."""
    try:
        as_.cancel_instance_refresh(AutoScalingGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ActiveInstanceRefreshNotFound":
            raise


def _run_concurrent(fns) -> list:
    """Invoke zero-arg callables concurrently; one outcome record per callable, in order."""

    def _wrap(fn):
        try:
            return {"ok": True, "value": fn(), "error_code": None, "error_message": None}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return {
                "ok": False,
                "value": None,
                "error_code": err.get("Code"),
                "error_message": err.get("Message"),
            }
        except Exception as exc:  # noqa: BLE001 - surface unexpected failures
            return {
                "ok": False,
                "value": None,
                "error_code": type(exc).__name__,
                "error_message": str(exc),
            }

    with ThreadPoolExecutor(max_workers=max(2, len(fns))) as pool:
        return list(pool.map(_wrap, fns))


def _concurrent_successes(results) -> int:
    return sum(1 for r in results if r["ok"])


def _concurrent_error_codes(results) -> list:
    return [r["error_code"] for r in results if not r["ok"]]


def _concurrent_error_messages(results) -> list:
    return [r["error_message"] for r in results if not r["ok"]]


_IN_PROGRESS_MESSAGE = (
    "An Instance Refresh is already in progress and blocks the execution of this Instance Refresh."
)

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Only one refresh may be active per group; concurrent starts are rejected and Cancel drives Cancelled."""
    as_ = ctx.client("autoscaling")
    env = _discover_env(ctx)

    name = _make_group(ctx, as_, env, min_size=1, max_size=1, desired_capacity=1)
    _wait_for_in_service(as_, name, 1, timeout_s=180)

    first = as_.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={
            "MinHealthyPercentage": 0,
            "InstanceWarmup": 600,
            "SkipMatching": False,
        },
    )["InstanceRefreshId"]
    # A long-warmup refresh holds the per-group lock for the whole check window, so
    # release it even if an assertion below fires first.
    ctx.on_cleanup(lambda: _cancel_if_active(as_, name))

    def start_again():
        return as_.start_instance_refresh(AutoScalingGroupName=name)

    results = _run_concurrent([start_again] * 4)
    successes = _concurrent_successes(results)
    assert successes == 0, (
        f"a second instance refresh must never be accepted while one is active: "
        f"{successes} of {len(results)} concurrent starts unexpectedly succeeded"
    )
    codes = _concurrent_error_codes(results)
    assert codes == ["InstanceRefreshInProgress"] * 4, (
        f"expected InstanceRefreshInProgress from every concurrent start, got {codes}"
    )
    messages = _concurrent_error_messages(results)
    assert messages == [_IN_PROGRESS_MESSAGE] * 4, (
        f"expected {_IN_PROGRESS_MESSAGE!r} from every concurrent start, got {messages}"
    )

    as_.cancel_instance_refresh(AutoScalingGroupName=name)
    _wait_for_refresh_status(as_, name, first, {"Cancelled"}, timeout_s=180)
    record = _refresh_record(as_, name, first)
    assert record["Status"] == "Cancelled", record
    assert record["InstanceRefreshId"] == first, record
    assert record["AutoScalingGroupName"] == name, record
    # A cancelled-but-in-flight replacement can still be launching/terminating; let the
    # group settle back to its steady state before it is safe to start another refresh.
    _wait_for_membership_settled(as_, name, 1, timeout_s=180)

    # Cancellation must release the per-group lock so a new refresh is accepted.
    second = as_.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={"MinHealthyPercentage": 0, "InstanceWarmup": 600},
    )["InstanceRefreshId"]
    assert second != first, f"a new refresh must get a fresh id, got {second!r} again"

    # Independent read at the destination: the new refresh must actually be recorded
    # as active, not just echoed back by the mutating call that created it.
    second_record = _refresh_record(as_, name, second)
    assert second_record is not None, (
        f"refresh {second} not found via an independent describe_instance_refreshes read"
    )
    assert second_record["Status"] in ("Pending", "InProgress"), second_record

    # Wait for the cancellation to actually land before returning: an ASG force-delete
    # racing a still-"Cancelling" refresh can be rejected, leaking the group and its
    # instance through cleanup that silently swallows a failed delete.
    as_.cancel_instance_refresh(AutoScalingGroupName=name)
    _wait_for_refresh_status(as_, name, second, {"Cancelled"}, timeout_s=180)
    # Settle again before returning: cleanup force-deletes the group next, and a
    # straggler instance not yet a tracked member can escape that delete's sweep.
    _wait_for_membership_settled(as_, name, 1, timeout_s=180)


def _own_vpc_and_subnet(ctx, ec2, instance_type="t3.micro", cidr="10.81.0.0/16",
                        subnet_cidr="10.81.1.0/24"):
    """A VPC and one subnet this check creates, in an available AZ that offers
    ``instance_type``. Each create registers its cleanup immediately."""
    tag = [{"Key": "sim2real", "Value": CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, f"no available AZ offers {instance_type!r}"
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=zones[0],
                                  TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}]
                                  )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits a 900 s cleanup budget.
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
