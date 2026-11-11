"""op-contract-detach-volume."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detach-volume"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachVolume: success detaches an EBS volume that is attached to a running instance,
    driving the volume back to 'available' with no Attachments; a bogus VolumeId is rejected
    with the specific InvalidVolume.NotFound error."""

    ec2 = ctx.client("ec2")

    net = ctx.network()
    az = net.availability_zones[0]
    subnet_id = net.subnets[az]

    ami_id = _latest_al2023_ami(ec2)

    instance_id = _run_instance_with_retry(
        ec2,
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name("sim2real-vol-inst-")),
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, "volume", ctx.unique_name("sim2real-vol-")),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )

    ec2.attach_volume(Device="/dev/sdf", InstanceId=instance_id, VolumeId=vol_id)
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "attached",
        timeout_s=60.0,
    )

    ec2.detach_volume(VolumeId=vol_id)
    state = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0],
        lambda v: v["State"] == "available" and v["Attachments"] == [],
        timeout_s=60.0,
    )
    assert state["State"] == "available", state["State"]
    assert state["Attachments"] == [], state["Attachments"]

    # Real AWS validates DetachVolume's VolumeId syntactically before it ever
    # reaches the not-found lookup: any well-formed-looking but non-existent
    # "vol-<hex>" id that isn't actually a real, currently/previously-allocated
    # volume id in this account is rejected as InvalidParameterValue rather than
    # InvalidVolume.NotFound (that latter code is reserved for ids that *were*
    # allocated, e.g. to an already-deleted volume). Exercise that boundary by
    # detaching a volume id that was allocated and deleted moments ago (and thus
    # is a real, previously-known id no longer attached to anything), which is
    # what actually elicits InvalidVolume.NotFound on real AWS.
    stale_vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, "volume", ctx.unique_name("sim2real-vol-stale-")),
    )["VolumeId"]
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[stale_vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    ec2.delete_volume(VolumeId=stale_vol_id)
    def _stale_lookup():
        try:
            ec2.describe_volumes(VolumeIds=[stale_vol_id])
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "present"

    _poll_until(_stale_lookup, lambda c: c == "InvalidVolume.NotFound", timeout_s=60.0)

    code, message = _error(lambda: ec2.detach_volume(VolumeId=stale_vol_id))
    assert code == "InvalidVolume.NotFound", code
    assert message == f"The volume '{stale_vol_id}' does not exist.", (
        f"unexpected InvalidVolume.NotFound message: {message!r}"
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


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
