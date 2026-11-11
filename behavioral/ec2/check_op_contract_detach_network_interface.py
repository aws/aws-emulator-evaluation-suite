"""op-contract-detach-network-interface."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detach-network-interface"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachNetworkInterface: success detaches a secondary ENI from a running instance,
    driving the interface back to 'available'; a bogus AttachmentId is rejected with the
    specific InvalidAttachmentID.NotFound error."""

    ec2 = ctx.client("ec2")

    subnet_id = ctx.network().subnet_ids[0]

    ami_id = _latest_al2023_ami(ec2)

    instance_id = _run_instance_with_retry(
        ec2,
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name("sim2real-eni-inst-")),
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "network-interface", ctx.unique_name("sim2real-eni-")),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    attachment_id = ec2.attach_network_interface(
        NetworkInterfaceId=eni_id, InstanceId=instance_id, DeviceIndex=1
    )["AttachmentId"]

    _poll_until(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])[
            "NetworkInterfaces"
        ][0]["Attachment"]["Status"],
        lambda s: s == "attached",
        timeout_s=60.0,
    )

    ec2.detach_network_interface(AttachmentId=attachment_id)

    status = _poll_until(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])[
            "NetworkInterfaces"
        ][0]["Status"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    assert status == "available", f"expected the detached ENI to settle at 'available', got {status!r}"

    # AttachmentId validation accepts only the 8-hex-char form; a 17-char id is rejected as
    # InvalidNetworkInterfaceAttachmentId.Malformed before the not-found lookup.
    code, message = _client_error(
        lambda: ec2.detach_network_interface(
            AttachmentId="eni-attach-1234abcd"
        )
    )
    assert code == "InvalidAttachmentID.NotFound", (
        f"expected InvalidAttachmentID.NotFound for a well-formed but nonexistent "
        f"AttachmentId, got {code!r}"
    )
    expected_message = "The interface attachment 'eni-attach-1234abcd' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the bogus detach must not have touched the ENI we already detached above.
    unaffected = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])[
        "NetworkInterfaces"
    ][0]["Status"]
    assert unaffected == "available", (
        f"a rejected detach on an unrelated AttachmentId must not change {eni_id}'s status; "
        f"got {unaffected!r}"
    )


# ===== helpers =====
def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real", "Value": "true"},
                {"Key": "sim2real-created", "Value": str(int(time.time()))},
            ],
        }
    ]


def _run_instance_with_retry(ec2, attempts=5, interval_s=3.0, **kwargs):
    """run_instances, tolerating the brief window where a just-created subnet has not
    yet propagated to every EC2 API code path (InvalidSubnetID.NotFound)."""
    last_exc = None
    for _ in range(attempts):
        try:
            return ec2.run_instances(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _latest_al2023_ami(ec2):
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI available in region")
    return images[0]["ImageId"]


def _terminate_and_wait(ec2, instance_id):
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

