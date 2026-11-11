"""get-instance-tpm-ek-pub-format-contract."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-instance-tpm-ek-pub-format-contract"
GROUP = "data-plane"
SERVICES = ["ec2"]

# NitroTPM-capable instance types per
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html
_NITRO_TPM_INSTANCE_TYPE = "m5.large"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInstanceTpmEkPub returns a structurally valid DER SubjectPublicKeyInfo for a NitroTPM instance."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_nitrotpm_windows_ami(ec2)
    if ami_id is None:
        raise AssertionError(
            "no NitroTPM-preconfigured Windows AMI (name pattern 'TPM-Windows_Server-*', "
            "owned by amazon) is available in this region/account; NitroTPM AMIs must be "
            "hand-built via RegisterImage otherwise, which this check does not do"
        )

    name = ctx.unique_name("sim2real-tpm-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=_NITRO_TPM_INSTANCE_TYPE,
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

    key_bytes_1 = _poll_tpm_ek_pub(ec2, instance_id, timeout_s=180.0, interval_s=10.0)
    assert key_bytes_1 is not None, "GetInstanceTpmEkPub never succeeded within the timeout"
    assert len(key_bytes_1) > 100, f"DER endorsement key blob suspiciously small: {len(key_bytes_1)} bytes"
    assert key_bytes_1[0] == 0x30, (
        f"DER-encoded SubjectPublicKeyInfo must open with a SEQUENCE tag (0x30); got {key_bytes_1[0]:#x}"
    )

    # The endorsement key is provisioned once at launch and must not be regenerated per call.
    resp2 = ec2.get_instance_tpm_ek_pub(InstanceId=instance_id, KeyType="rsa-2048", KeyFormat="der")
    key_bytes_2 = base64.b64decode(resp2["KeyValue"])
    assert key_bytes_2 == key_bytes_1, "the TPM endorsement key differed between two consecutive reads"


def _latest_nitrotpm_windows_ami(ec2):
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["TPM-Windows_Server-*"]},
            {"Name": "platform", "Values": ["windows"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp["Images"]
    if not images:
        return None
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _poll_tpm_ek_pub(ec2, instance_id, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ec2.get_instance_tpm_ek_pub(
                InstanceId=instance_id, KeyType="rsa-2048", KeyFormat="der"
            )
            key_value = resp.get("KeyValue")
            if key_value:
                return base64.b64decode(key_value)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IncorrectInstanceState", "InvalidInstanceID.NotFound"):
                raise
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
