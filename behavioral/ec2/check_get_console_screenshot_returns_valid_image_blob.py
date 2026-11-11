"""get-console-screenshot-returns-valid-image-blob."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-console-screenshot-returns-valid-image-blob"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetConsoleScreenshot's base64 blob decodes to a real JPEG (SOI/EOI markers), not a stub."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_amazon_linux_ami(ec2)
    name = ctx.unique_name("sim2real-console-shot-")

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

    image_bytes = _poll_console_screenshot(ec2, instance_id, timeout_s=300.0, interval_s=15.0)
    assert image_bytes is not None, "GetConsoleScreenshot never succeeded within the timeout"
    assert len(image_bytes) > 500, f"screenshot payload suspiciously small: {len(image_bytes)} bytes"
    assert image_bytes[:2] == b"\xff\xd8", (
        f"decoded screenshot is missing the JPEG SOI marker; got header {image_bytes[:4]!r}"
    )
    assert image_bytes[-2:] == b"\xff\xd9", (
        f"decoded screenshot is missing the JPEG EOI marker; got trailer {image_bytes[-4:]!r}"
    )


def _latest_amazon_linux_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )
    images = resp["Images"]
    assert images, "no al2023-ami-*-x86_64 AMI found owned by amazon in this region"
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _poll_console_screenshot(ec2, instance_id, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ec2.get_console_screenshot(InstanceId=instance_id)
            image_data = resp.get("ImageData")
            if image_data:
                return base64.b64decode(image_data)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IncorrectInstanceState", "InvalidInstanceID.NotFound"):
                raise
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
