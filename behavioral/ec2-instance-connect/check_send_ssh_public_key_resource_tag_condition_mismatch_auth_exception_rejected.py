"""send-ssh-public-key-resource-tag-condition-mismatch-auth-exception-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-ssh-public-key-resource-tag-condition-mismatch-auth-exception-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2-instance-connect"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity allowed SendSSHPublicKey only on instances tagged sim2real-team=green is refused with
    AccessDeniedException and the exact message for an instance tagged blue, and the same call succeeds once
    the instance is retagged green.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    subnet_id = _create_subnet(ctx, ec2)
    ami_id = _latest_al2_ami(ec2)
    instance_id = _launch_instance(ctx, ec2, ami_id, subnet_id, team_tag="blue")

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2-instance-connect:SendSSHPublicKey",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:ResourceTag/sim2real-team": "green"}},
            }
        ],
    }
    user_arn, access_key_id, secret_access_key = _create_restricted_identity(ctx, iam, allow_policy)
    restricted_eic = ctx.client(
        "ec2-instance-connect",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )

    pub1 = _fake_rsa_pubkey()

    def _push():
        return restricted_eic.send_ssh_public_key(
            InstanceId=instance_id, InstanceOSUser="ec2-user", SSHPublicKey=pub1
        )

    code, message = _poll_stable_error(_push, timeout_s=120.0, interval_s=4.0)
    assert code == "AccessDeniedException", f"CODE={code!r}"
    partition, account = user_arn.split(":")[1], user_arn.split(":")[4]
    instance_arn = f"arn:{partition}:ec2:{ec2.meta.region_name}:{account}:instance/{instance_id}"
    assert message == (
        f"User: {user_arn} is not authorized to perform: ec2-instance-connect:SendSSHPublicKey "
        f"on resource: {instance_arn} because no identity-based policy allows the "
        "ec2-instance-connect:SendSSHPublicKey action"
    ), message


    # Break exactly the tag value, nothing else: retag the SAME instance to match the condition.
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "sim2real-team", "Value": "green"}])

    pub2 = _fake_rsa_pubkey()

    def _push2():
        return restricted_eic.send_ssh_public_key(
            InstanceId=instance_id, InstanceOSUser="ec2-user", SSHPublicKey=pub2
        )

    success = _poll_until_success(_push2, timeout_s=45.0, interval_s=3.0)
    assert success is True, f"SendSSHPublicKey after retagging to a matching resource tag should have succeeded, got Success={success!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


_TRANSIENT_CREDENTIAL_CODES = {"InvalidClientTokenId", "AuthFailure", "AccessDenied", "UnrecognizedClientException"}


def _poll_stable_error(fn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        last_code, last_message = _error(fn)
        if last_code not in _TRANSIENT_CREDENTIAL_CODES:
            return last_code, last_message
        time.sleep(interval_s)
    raise AssertionError(f"credentials never stabilized past propagation errors within {timeout_s}s: {last_code}")


def _poll_until_success(fn, timeout_s=45.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = fn()
            return resp["Success"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"push never succeeded after retagging within {timeout_s}s (last error: {last_code})")


def _create_restricted_identity(ctx, iam, policy_document):
    username = ctx.unique_name("sim2real-eic-taguser-")
    user_arn = iam.create_user(UserName=username)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))
    policy_name = "sim2real-eic-tag-policy"
    iam.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=username, PolicyName=policy_name))
    key = iam.create_access_key(UserName=username)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"]))
    return user_arn, key["AccessKeyId"], key["SecretAccessKey"]


def _create_subnet(ctx, ec2):
    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eic-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.95.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eic-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


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


def _launch_instance(ctx, ec2, ami_id, subnet_id, instance_type="t3.micro", team_tag="blue"):
    name = ctx.unique_name("sim2real-eic-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "sim2real-team", "Value": team_tag},
                ],
            }
        ],
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
    """Structurally-valid (SSH-wire-format-correct) RSA public key, no paramiko/cryptography
    needed. Not a real usable key pair -- only sufficient for the API-level checks here."""
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
