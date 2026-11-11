"""op-contract-attachNetworkInterface."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-attachNetworkInterface"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachNetworkInterface plugs a secondary ENI into a running instance; nonexistent instance rejected."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    vpc = ec2.create_vpc(
        CidrBlock="10.203.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eni-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_vpc(VpcId=vpc)))
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.203.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eni-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_subnet(SubnetId=subnet)))

    ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")[
        "Parameter"
    ]["Value"]

    name = ctx.unique_name("sim2real-eni-instance-")
    instance = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Instances"][0]["InstanceId"]

    def cleanup_instance():
        _cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance]))
        _cleanup(
            lambda: ctx.client("ec2").get_waiter("instance_terminated").wait(InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        )

    ctx.on_cleanup(cleanup_instance)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    eni = ec2.create_network_interface(
        SubnetId=subnet,
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eni-")}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni)))

    # error boundary: instance does not exist. Note: AttachNetworkInterface validates
    # instance-ID format more strictly than most EC2 APIs -- even a length-correct, mixed-hex
    # 17-char ID like "i-0123456789abcdef0" comes back as "...Malformed" rather than
    # "...NotFound" here (confirmed against real AWS), so that is the code this rejection path
    # actually surfaces.
    code, message = _error_of(
        lambda: ec2.attach_network_interface(NetworkInterfaceId=eni, InstanceId="i-0123456789abcdef0", DeviceIndex=1)
    )
    assert code == "InvalidInstanceID.Malformed", f"expected InvalidInstanceID.Malformed, got {code}"
    assert message == 'Invalid id: "i-0123456789abcdef0"', message
    rejected = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])["NetworkInterfaces"][0]
    assert "Attachment" not in rejected, (
        f"a rejected AttachNetworkInterface must leave the ENI with no Attachment, got {rejected.get('Attachment')}"
    )

    # success path
    attachment_id = ec2.attach_network_interface(NetworkInterfaceId=eni, InstanceId=instance, DeviceIndex=1)[
        "AttachmentId"
    ]

    def cleanup_attachment():
        _cleanup(lambda: ec2.detach_network_interface(AttachmentId=attachment_id, Force=True))
        _cleanup(
            lambda: _poll_until(
                lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])["NetworkInterfaces"][0][
                    "Status"
                ],
                lambda s: s == "available",
                timeout_s=60,
                interval_s=3,
            )
        )

    ctx.on_cleanup(cleanup_attachment)

    final = _poll_until(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])["NetworkInterfaces"][0],
        lambda ni: ni.get("Attachment", {}).get("Status") == "attached",
        timeout_s=60,
        interval_s=3,
    )
    assert final["Attachment"]["InstanceId"] == instance, (
        f"expected attachment to point at {instance}, got {final['Attachment']['InstanceId']!r}"
    )
    assert final["Attachment"]["DeviceIndex"] == 1, (
        f"expected DeviceIndex 1, got {final['Attachment']['DeviceIndex']}"
    )


# ===== helpers =====
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
    "InvalidInstanceID.NotFound", "InvalidAttachmentID.NotFound", "InvalidVolume.NotFound",
})
_BUSY = frozenset({"DependencyViolation", "InvalidNetworkInterface.InUse", "VolumeInUse"})


def _cleanup(fn: Callable[[], Any], *done_codes: str) -> None:
    """Run one teardown call: a resource already gone (or a code in done_codes) returns; one AWS
    is still releasing is retried every 2 s for up to 30 s; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE or code in done_codes:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        if err.get("Code") is None:
            raise
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
