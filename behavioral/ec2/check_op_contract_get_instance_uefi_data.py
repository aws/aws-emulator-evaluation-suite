"""op-contract-get-instance-uefi-data."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "op-contract-get-instance-uefi-data"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInstanceUefiData returns the base64-encoded, AMZNUEFI-tagged UEFI variable
    store for a running UEFI-boot instance; a nonexistent instance ID is rejected."""
    ec2 = ctx.client("ec2")

    image_id = _latest_amazon_ami(ec2)
    instance_id = _launch_uefi_instance(ctx, ec2, image_id)

    # The UEFI variable store snapshot isn't necessarily available the
    # instant the instance reaches "running" -- the instance state reflects
    # the hypervisor lifecycle, not that the guest has finished booting far
    # enough to have a UEFI NVRAM snapshot ready to serve. Poll with a
    # bounded budget instead of assuming it's ready immediately.
    resp = _poll_until_uefi_data(ec2, instance_id)
    assert resp["InstanceId"] == instance_id, (
        f"expected InstanceId {instance_id}, got {resp.get('InstanceId')!r}"
    )
    raw_uefi_data = resp["UefiData"]
    assert isinstance(raw_uefi_data, str) and len(raw_uefi_data) > 0, (
        f"expected a non-empty UefiData string, got {raw_uefi_data!r}"
    )

    # Not just base64-wrapped opaque bytes: AWS's own UEFI variable store snapshot
    # is stamped with an "AMZNUEFI" magic header (confirmed against real AWS), so
    # a target that returns arbitrary non-empty text in its place cannot pass this.
    decoded = base64.b64decode(raw_uefi_data, validate=True)
    assert decoded[:8] == b"AMZNUEFI", (
        f"expected the AMZNUEFI magic header on decoded UefiData, got {decoded[:8]!r}"
    )

    # EC2 validates more of an instance ID than its prefix and length, so some
    # IDs derived from the real one by changing its trailing hex digit are
    # refused as InvalidInstanceID.Malformed. The first derived ID EC2 accepts as
    # well formed is the probe for the absent-instance contract.
    fake_instance_id, code, message = _first_well_formed_absent_id(ec2, instance_id)
    assert code == "InvalidInstanceID.NotFound", f"expected InvalidInstanceID.NotFound, got {code}: {message!r}"
    expected_message = f"The instance ID '{fake_instance_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_until_uefi_data(ec2, instance_id: str, attempts: int = 20, delay: float = 15.0) -> dict:
    import time

    last_resp = None
    for _ in range(attempts):
        last_resp = ec2.get_instance_uefi_data(InstanceId=instance_id)
        if last_resp.get("UefiData"):
            return last_resp
        time.sleep(delay)
    raise AssertionError(
        f"GetInstanceUefiData never returned a non-empty UefiData for {instance_id} "
        f"within {attempts * delay:.0f}s; last response: {last_resp}"
    )


def _first_well_formed_absent_id(ec2, real_id: str):
    """Try each ID that differs from real_id only in its trailing hex digit and
    return (id, code, message) for the first one EC2 does not refuse as
    malformed. Raises if EC2 refuses every candidate as malformed."""
    prefix, _, hexpart = real_id.rpartition("-")
    refused = []
    for digit in "0123456789abcdef":
        if digit == hexpart[-1]:
            continue
        candidate = f"{prefix}-{hexpart[:-1]}{digit}"
        code, message = _client_error(lambda: ec2.get_instance_uefi_data(InstanceId=candidate))
        if code != "InvalidInstanceID.Malformed":
            return candidate, code, message
        refused.append(candidate)
    raise AssertionError(f"every derived instance ID was refused as malformed: {refused}")


def _latest_amazon_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            # BootMode is a property of the AMI, not something RunInstances can
            # override at launch time -- select an AMI that already boots UEFI.
            {"Name": "boot-mode", "Values": ["uefi-preferred", "uefi"]},
        ],
    )["Images"]
    assert images, "no UEFI-capable Amazon Linux 2023 AMI found to test against"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_uefi_instance(ctx, ec2, image_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-uefi-")
    resp = ec2.run_instances(
        ImageId=image_id,
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
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
