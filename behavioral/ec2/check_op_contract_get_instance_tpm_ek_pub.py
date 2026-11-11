"""op-contract-get-instance-tpm-ek-pub."""
from __future__ import annotations

import time

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-instance-tpm-ek-pub"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# TpmSupport is set on the AMI (RegisterImage), never on RunInstances; AWS never shipped
# a preconfigured NitroTPM Linux AMI, but does ship one for Windows. See
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html and
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html
# for the instance-type requirement.
_NITRO_TPM_INSTANCE_TYPE = "m5.large"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInstanceTpmEkPub returns the NitroTPM endorsement key for a running,
    TpmSupport-enabled instance; an unsupported key format/type combination is
    rejected with a distinct, specific error."""
    ec2 = ctx.client("ec2")

    image_id = _latest_nitrotpm_windows_ami(ec2)
    instance_id = _launch_tpm_instance(ctx, ec2, image_id)

    resp = _poll_tpm_ek_pub(ec2, instance_id, key_format="der", key_type="rsa-2048")
    assert resp["InstanceId"] == instance_id, f"expected InstanceId {instance_id}, got {resp['InstanceId']}"
    assert resp["KeyFormat"] == "der", f"expected KeyFormat der, got {resp['KeyFormat']}"
    assert resp["KeyType"] == "rsa-2048", f"expected KeyType rsa-2048, got {resp['KeyType']}"
    assert resp["KeyValue"], "expected a non-empty endorsement key"

    code, message = _error(
        lambda: ec2.get_instance_tpm_ek_pub(
            InstanceId=instance_id, KeyFormat="pem", KeyType="rsa-2048"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "Invalid parameter value provided", message


def _latest_nitrotpm_windows_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["TPM-Windows_Server-*"]},
            {"Name": "platform", "Values": ["windows"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, (
        "no NitroTPM-preconfigured Windows AMI (name pattern 'TPM-Windows_Server-*', "
        "owned by amazon) found in this region to test against"
    )
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_tpm_instance(ctx, ec2, image_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-tpm-")
    resp = ec2.run_instances(
        ImageId=image_id,
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
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


def _poll_tpm_ek_pub(ec2, instance_id: str, *, key_format: str, key_type: str,
                      timeout_s: float = 300.0, interval_s: float = 10.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return ec2.get_instance_tpm_ek_pub(
                InstanceId=instance_id, KeyFormat=key_format, KeyType=key_type
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code not in (
                "InstanceTpmEkPub.NotFound",
                "IncorrectInstanceState",
                "InvalidInstanceID.NotFound",
            ):
                raise
        time.sleep(interval_s)
    raise AssertionError(
        f"GetInstanceTpmEkPub never succeeded for {instance_id} within {timeout_s}s; "
        f"last error {last_code}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
