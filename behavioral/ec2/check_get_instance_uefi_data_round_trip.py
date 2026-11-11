"""get-instance-uefi-data-round-trip."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-instance-uefi-data-round-trip"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetInstanceUefiData returns the UEFI variable store persisted at boot, stable across reads."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_uefi_amazon_linux_ami(ec2)
    name = ctx.unique_name("sim2real-uefi-")

    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    data_1 = _poll_uefi_data(ec2, instance_id, timeout_s=240.0, interval_s=15.0)
    assert data_1 is not None, "GetInstanceUefiData never returned data within the timeout"
    assert len(data_1) > 200, f"UEFI variable store payload suspiciously small: {len(data_1)} bytes"

    # The UEFI variable store is what the instance actually persisted at boot: a second read
    # must return byte-identical content, not freshly (re)generated placeholder bytes.
    resp2 = ec2.get_instance_uefi_data(InstanceId=instance_id)
    data_2 = base64.b64decode(resp2["UefiData"])
    assert data_2 == data_1, "GetInstanceUefiData returned different bytes on a second, unmodified read"


def _latest_uefi_amazon_linux_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
            {"Name": "boot-mode", "Values": ["uefi-preferred", "uefi"]},
        ],
    )
    images = resp["Images"]
    assert images, "no UEFI-capable al2023-ami-*-x86_64 AMI found owned by amazon in this region"
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _poll_uefi_data(ec2, instance_id, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ec2.get_instance_uefi_data(InstanceId=instance_id)
            uefi_data = resp.get("UefiData")
            if uefi_data:
                return base64.b64decode(uefi_data)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IncorrectInstanceState", "InvalidInstanceID.NotFound"):
                raise
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
