"""send-ssh-public-key-nonexistent-instance-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-ssh-public-key-nonexistent-instance-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2-instance-connect"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendSSHPublicKey for a well-formed instance id that DescribeInstances does not know is refused with
    EC2InstanceNotFoundException "Instance not found.", while the same call for a running instance succeeds.
    """
    eic = ctx.client("ec2-instance-connect")
    ec2 = ctx.client("ec2")

    subnet_id, _vpc_id, _az = _default_subnet(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ec2)
    instance_id = _launch_instance(ctx, ec2, ami_id, subnet_id)

    # Positive control: the identical call succeeds against a real, running instance.
    control_key = _fake_rsa_pubkey()
    resp = eic.send_ssh_public_key(InstanceId=instance_id, InstanceOSUser="ec2-user", SSHPublicKey=control_key)
    assert resp["Success"] is True

    bogus_instance_id = "i-" + uuid.uuid4().hex[:17]
    # Confirm DescribeInstances does not know the id before asserting on it.
    described = ec2.describe_instances(
        Filters=[{"Name": "instance-id", "Values": [bogus_instance_id]}]
    )
    assert described["Reservations"] == []

    # A wire-format-valid RSA key (not a usable key pair), so key-format validation cannot mask the
    # not-found answer if it runs before the instance lookup.
    good_key = _fake_rsa_pubkey()

    def _push():
        eic.send_ssh_public_key(InstanceId=bogus_instance_id, InstanceOSUser="ec2-user", SSHPublicKey=good_key)

    code, message = _error_of(_push)
    assert code == "EC2InstanceNotFoundException", f"CODE={code!r}"
    assert message == "Instance not found.", f"MESSAGE={message!r}"


def _error_of(fn):
    """(ErrorCode, ErrorMessage) of the ClientError *fn* must raise; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _default_subnet(ec2, *, ctx):
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no shared network VPC/subnet available in this account/region to launch a test instance")
    subnet = subnets[0]
    return subnet["SubnetId"], subnet["VpcId"], subnet["AvailabilityZone"]


def _latest_al2_ami(ec2):
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        raise AssertionError("no Amazon Linux 2 AMI found in this region")
    return images[0]["ImageId"]


def _launch_instance(ctx, ec2, ami_id, subnet_id, instance_type="t3.micro"):
    name = ctx.unique_name("sim2real-eic-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _ssh_string(b: bytes) -> bytes:
    import struct

    return struct.pack(">I", len(b)) + b


def _mpint(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    nbytes = (i.bit_length() + 7) // 8
    b = i.to_bytes(nbytes, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def _fake_rsa_pubkey(bits: int = 2048) -> str:
    """Build a structurally-valid (SSH-wire-format-correct) RSA public key string without
    paramiko/cryptography (neither is installed in this runtime). It is not a real usable key
    pair -- only sufficient for exercising SendSSHPublicKey's format validation/Success path,
    never for an actual SSH login."""
    import base64
    import os

    e = 65537
    n_bytes = bytearray(os.urandom(bits // 8))
    n_bytes[0] |= 0x80
    n_bytes[-1] |= 0x01
    n = int.from_bytes(bytes(n_bytes), "big")
    blob = _ssh_string(b"ssh-rsa") + _ssh_string(_mpint(e)) + _ssh_string(_mpint(n))
    return "ssh-rsa " + base64.b64encode(blob).decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
