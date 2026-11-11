"""op-contract-modify-traffic-mirror-session."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-traffic-mirror-session"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTrafficMirrorSession: changing PacketLength is observable on
    DescribeTrafficMirrorSessions, and a grossly out-of-range PacketLength (far
    beyond any plausible frame size) is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)
    name = ctx.unique_name("sim2real-behav-tms-")
    ami_id = _latest_amazon_linux_ami(ctx)

    # Traffic mirror targets (and sessions) require their network interface to be
    # attached to a supported (current-generation/Nitro) instance -- a bare,
    # unattached ENI is rejected with NetworkInterfaceNotSupported on real AWS. So
    # launch an instance and use its primary ENI as the mirror source, and attach a
    # second ENI to the same instance to use as the mirror target.
    reservation = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[_tag_spec("instance", name)],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    try:
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
        )
    except Exception as e:
        raise AssertionError(f"instance never reached running state: {e}")

    described_instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    source_eni_id = described_instance["NetworkInterfaces"][0]["NetworkInterfaceId"]

    target_eni = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name + "tgt")]
    )["NetworkInterface"]
    target_eni_id = target_eni["NetworkInterfaceId"]
    attachment = ec2.attach_network_interface(
        NetworkInterfaceId=target_eni_id, InstanceId=instance_id, DeviceIndex=1
    )
    attachment_id = attachment["AttachmentId"]

    def _detach_and_delete_eni():
        try:
            ec2.detach_network_interface(AttachmentId=attachment_id, Force=True)
            _poll_until(
                lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[target_eni_id])[
                    "NetworkInterfaces"
                ][0]["Status"],
                lambda s: s == "available",
                timeout_s=60,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidAttachmentID.NotFound",
                "InvalidNetworkInterfaceID.NotFound",
            ):
                raise
        try:
            ec2.delete_network_interface(NetworkInterfaceId=target_eni_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                raise

    ctx.on_cleanup(_detach_and_delete_eni)

    _poll_until(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[target_eni_id])["NetworkInterfaces"][0][
            "Status"
        ],
        lambda s: s == "in-use",
        timeout_s=60,
    )

    target = ec2.create_traffic_mirror_target(
        NetworkInterfaceId=target_eni_id, TagSpecifications=[_tag_spec("traffic-mirror-target", name)]
    )["TrafficMirrorTarget"]
    target_id = target["TrafficMirrorTargetId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_target(TrafficMirrorTargetId=target_id))

    filt = ec2.create_traffic_mirror_filter(
        Description="behavioral test filter", TagSpecifications=[_tag_spec("traffic-mirror-filter", name)]
    )["TrafficMirrorFilter"]
    filter_id = filt["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    session = ec2.create_traffic_mirror_session(
        NetworkInterfaceId=source_eni_id,
        TrafficMirrorTargetId=target_id,
        TrafficMirrorFilterId=filter_id,
        SessionNumber=1,
        PacketLength=100,
        TagSpecifications=[_tag_spec("traffic-mirror-session", name)],
    )["TrafficMirrorSession"]
    session_id = session["TrafficMirrorSessionId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_session(TrafficMirrorSessionId=session_id))
    assert session["PacketLength"] == 100, session

    # success path
    modified = ec2.modify_traffic_mirror_session(TrafficMirrorSessionId=session_id, PacketLength=200)[
        "TrafficMirrorSession"
    ]
    assert modified["PacketLength"] == 200, modified
    described = ec2.describe_traffic_mirror_sessions(TrafficMirrorSessionIds=[session_id])[
        "TrafficMirrorSessions"
    ][0]
    assert described["PacketLength"] == 200, described

    # error boundary: real AWS did not reject 9000 (the documented 8500-byte max
    # appears not to be strictly enforced at that boundary), so use a value far
    # beyond any plausible frame size to reliably hit the validation error.
    err, err_message = _error_code(
        lambda: ec2.modify_traffic_mirror_session(TrafficMirrorSessionId=session_id, PacketLength=1000000)
    )
    assert err == "InvalidParameterValue", err
    assert err_message == "PacketLength is outside the allowed range of 1-65535", (
        f"expected the exact InvalidParameterValue message AWS returns, got {err_message!r}"
    )

    # effect-absent: the rejected call must not have moved PacketLength off its last-good value.
    after_reject = ec2.describe_traffic_mirror_sessions(TrafficMirrorSessionIds=[session_id])[
        "TrafficMirrorSessions"
    ][0]
    assert after_reject["PacketLength"] == 200, after_reject


def _terminate_and_wait(ctx, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return
        raise
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available and must not turn
    into an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _latest_amazon_linux_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _create_vpc_and_subnet(ctx):
    # Prefer reusing an existing VPC/subnet (e.g. the run's shared network) to avoid
    # tripping the per-account VpcLimitExceeded quota; only create a fresh VPC/subnet
    # if nothing reusable is available.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        for subnet in subnets:
            if subnet.get("AvailableIpAddressCount", 0) > 0:
                return vpc["VpcId"], subnet["SubnetId"]

    name = ctx.unique_name("sim2real-behav-net-")
    vpc = ec2.create_vpc(CidrBlock="10.84.0.0/24", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.84.0.0/28", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

