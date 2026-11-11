"""dwin-windows-password-data-decrypts-with-its-key-pair."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dwin-windows-password-data-decrypts-with-its-key-pair"
GROUP = 'windows-guest'
SERVICES = ['ec2', 'ssm']

_WINDOWS_AMI_PARAM = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
_LINUX_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_WINDOWS_TYPE = "t3.large"
_LINUX_TYPE = "t3.micro"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


@tags(
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A Windows instance's password data decrypts with its launch key pair's private key to an
    Administrator password, does not decrypt with another key pair, and a Linux instance launched
    from the same key pair in the same subnet never produces any.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetPasswordData.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    # --- everything decidable, before the first create ------------------------
    windows_az = _usable_az(ec2, _WINDOWS_TYPE)
    linux_offered = _azs_offering(ec2, _LINUX_TYPE)
    assert windows_az in linux_offered, (
        f"the absence leg must differ ONLY in the platform, so both instance types must be "
        f"offered in one AZ; {windows_az!r} offers {_WINDOWS_TYPE} but {_LINUX_TYPE} is offered "
        f"only in {sorted(linux_offered)!r}"
    )
    windows_ami = ssm.get_parameter(Name=_WINDOWS_AMI_PARAM)["Parameter"]["Value"]
    linux_ami = ssm.get_parameter(Name=_LINUX_AMI_PARAM)["Parameter"]["Value"]
    windows_image = ec2.describe_images(ImageIds=[windows_ami])["Images"][0]
    linux_image = ec2.describe_images(ImageIds=[linux_ami])["Images"][0]
    assert windows_image["Platform"] == "windows", (
        f"{_WINDOWS_AMI_PARAM} must resolve to a Windows image; {windows_ami} reports "
        f"Platform={windows_image.get('Platform')!r} Name={windows_image.get('Name')!r}"
    )
    assert "Platform" not in linux_image, (
        f"{_LINUX_AMI_PARAM} must resolve to a non-Windows image (EC2 sets Platform only for "
        f"Windows); {linux_ami} reports Platform={linux_image.get('Platform')!r}"
    )

    # --- the key pair the Windows password will be encrypted to ---------------
    key_name = ctx.unique_name("sim2real-dwin-kp-")
    key_pair = ec2.create_key_pair(
        KeyName=key_name, KeyType="rsa", KeyFormat="pem",
        TagSpecifications=[{"ResourceType": "key-pair",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=key_name))
    modulus, exponent = _rsa_private(key_pair["KeyMaterial"])

    other_name = ctx.unique_name("sim2real-dwin-kp-other-")
    other_pair = ec2.create_key_pair(
        KeyName=other_name, KeyType="rsa", KeyFormat="pem",
        TagSpecifications=[{"ResourceType": "key-pair",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=other_name))
    other_modulus, other_exponent = _rsa_private(other_pair["KeyMaterial"])
    assert other_modulus != modulus, (
        "two CreateKeyPair calls must mint different RSA moduli, otherwise the wrong-key leg "
        "below proves nothing"
    )

    # --- a private network of this check's own making -------------------------
    # No internet gateway: password generation happens in the guest and is read out of the
    # console by EC2 itself, so this leg needs no egress at all.
    net = _private_network(ctx, ec2, windows_az)

    # --- the Windows instance -------------------------------------------------
    windows_id = _launch(ctx, ec2, ImageId=windows_ami, InstanceType=_WINDOWS_TYPE,
                         KeyName=key_name, SubnetId=net["subnet_id"],
                         SecurityGroupIds=[net["group_id"]])

    # --- the effect: a blob that decrypts with THIS key pair ------------------
    windows_password = _poll(
        lambda: ec2.get_password_data(InstanceId=windows_id),
        lambda r: bool(r["PasswordData"]),
        timeout_s=1200, interval_s=15.0,
        what=f"Windows instance {windows_id} publishing its encrypted Administrator password",
    )
    assert windows_password["InstanceId"] == windows_id, (
        f"the password data is keyed to {windows_password['InstanceId']!r}, not the instance it "
        f"was requested for ({windows_id!r})"
    )
    ciphertext = base64.b64decode(windows_password["PasswordData"], validate=True)
    key_bytes = (modulus.bit_length() + 7) // 8
    assert len(ciphertext) == key_bytes, (
        f"password data must be one RSA block under the launch key pair's {modulus.bit_length()}-"
        f"bit modulus ({key_bytes} bytes); the blob decodes to {len(ciphertext)} bytes"
    )
    password = _rsa_decrypt(ciphertext, modulus, exponent)
    assert len(password) >= 12, (
        f"the decrypted Administrator password is {len(password)} characters "
        f"({password[:2]!r}...), which is too short to be the generated one"
    )
    assert password.isprintable(), (
        f"the decrypted password must be printable ASCII, got {password!r}"
    )
    assert not any(c.isspace() for c in password), (
        f"the decrypted password must contain no whitespace, got {password!r}"
    )

    # --- absence 1: the same blob under a DIFFERENT key pair ------------------
    wrong = _decrypt_failure(ciphertext, other_modulus, other_exponent)
    assert wrong is not None, (
        f"password data encrypted for key pair {key_name!r} must NOT decrypt under key pair "
        f"{other_name!r}; it yielded {_rsa_decrypt(ciphertext, other_modulus, other_exponent)!r}"
    )

    # --- absence 2: the same key pair, the same subnet, Linux instead ---------
    linux_id = _launch(ctx, ec2, ImageId=linux_ami, InstanceType=_LINUX_TYPE,
                       KeyName=key_name, SubnetId=net["subnet_id"],
                       SecurityGroupIds=[net["group_id"]])
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[linux_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    # Polled over a window the Windows instance had already beaten, so "still empty" is a
    # property of the platform and not of having asked too early.
    deadline = time.monotonic() + 120
    while True:
        linux_password = ec2.get_password_data(InstanceId=linux_id)
        assert linux_password["PasswordData"] == "", (
            f"a Linux instance launched from key pair {key_name!r} must never publish password "
            f"data; {linux_id} returned {linux_password['PasswordData']!r}"
        )
        assert linux_password["InstanceId"] == linux_id, linux_password
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    # ... while the Windows blob from the same run is still there: the positive control.
    assert ec2.get_password_data(InstanceId=windows_id)["PasswordData"] != "", (
        f"the Windows instance {windows_id} stopped reporting password data, so the empty Linux "
        f"result cannot be attributed to the platform"
    )


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _retry_delete(fn, codes=("DependencyViolation", "InvalidParameterValue"),
                  attempts=20, delay=10.0):
    """Retry a delete that only succeeds once a reference is released, then let the final raise
    surface: ctx.on_cleanup swallows exceptions, so a leak would otherwise be silent."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound") or code in ("NoSuchEntity", "InvalidGroup.NotFound"):
                return None
            if code in codes and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise
    raise last


def _tag_spec(ctx, resource_types):
    """Tag specifications for every EC2 resource this check creates."""
    return [
        {"ResourceType": rt,
         "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dwin-")},
                  {"Key": "sim2real", "Value": CHECK}]}
        for rt in resource_types
    ]


def _azs_offering(ec2, instance_type):
    """The AZs that both are available and offer the instance type. AZ names map to different
    physical zones in different accounts, so none is hardcoded."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = offered & available
    assert usable, (
        f"no available AZ in this region offers {instance_type}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    return usable


def _usable_az(ec2, instance_type):
    return sorted(_azs_offering(ec2, instance_type))[0]


def _private_network(ctx, ec2, az):
    """A VPC, subnet and security group created here, so no default VPC is required."""
    vpc = ec2.create_vpc(
        CidrBlock="10.90.0.0/16", TagSpecifications=_tag_spec(ctx, ("vpc",)),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.90.1.0/24", AvailabilityZone=az,
        TagSpecifications=_tag_spec(ctx, ("subnet",)),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dwin-sg-"), Description="sim2real dwin password data",
        VpcId=vpc, TagSpecifications=_tag_spec(ctx, ("security-group",)),
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=group)))
    return {"vpc_id": vpc, "subnet_id": subnet, "group_id": group}


def _launch(ctx, ec2, **kwargs):
    """Run one instance and register its termination BEFORE anything else can fail."""
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            MinCount=1, MaxCount=1,
            TagSpecifications=_tag_spec(ctx, ("instance", "volume")),
            **kwargs,
        )
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    return instance_id


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for `terminated`, so the network it sits in can then be deleted."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [
            i["State"]["Name"]
            for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            for i in r["Instances"]
        ]
        if all(s == "terminated" for s in states):
            return
        time.sleep(10)


def _der_read(buf, offset):
    """One DER TLV at *offset*: its tag, its contents, and the offset just past it."""
    tag = buf[offset]
    offset += 1
    length = buf[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(buf[offset:offset + count], "big")
        offset += count
    return tag, buf[offset:offset + length], offset + length


def _rsa_private(pem):
    """(modulus, private exponent) from the PKCS#1 private key CreateKeyPair returns."""
    body = "".join(line for line in pem.splitlines() if "-----" not in line)
    der = base64.b64decode(body)
    tag, sequence, _ = _der_read(der, 0)
    assert tag == 0x30, f"a PKCS#1 private key must be a DER SEQUENCE, first tag was {tag:#x}"
    offset = 0
    integers = []
    for _ in range(4):  # version, modulus, publicExponent, privateExponent
        tag, contents, offset = _der_read(sequence, offset)
        assert tag == 0x02, f"expected a DER INTEGER in the key, got tag {tag:#x}"
        integers.append(int.from_bytes(contents, "big"))
    assert integers[0] == 0, f"unexpected PKCS#1 key version {integers[0]!r}"
    return integers[1], integers[3]


def _rsa_decrypt(ciphertext, modulus, exponent):
    """The plaintext of one PKCS#1 v1.5 RSA block, or None if the block is not valid under this
    key. Stdlib only: this check must not depend on a third-party crypto library being present."""
    plain = pow(int.from_bytes(ciphertext, "big"), exponent, modulus)
    block = plain.to_bytes((modulus.bit_length() + 7) // 8, "big")
    if block[0] != 0x00 or block[1] != 0x02:
        return None
    separator = block.find(b"\x00", 2)
    if separator < 0:
        return None
    try:
        return block[separator + 1:].decode("ascii")
    except UnicodeDecodeError:
        return None


def _decrypt_failure(ciphertext, modulus, exponent):
    """A short reason why this key cannot read this block, or None if it CAN — the absence leg
    must not be able to report success as a failure."""
    plain = pow(int.from_bytes(ciphertext, "big"), exponent, modulus)
    block = plain.to_bytes((modulus.bit_length() + 7) // 8, "big")
    if block[0] != 0x00 or block[1] != 0x02:
        return f"not a PKCS#1 v1.5 block under this key: leading bytes {block[:2]!r}"
    if block.find(b"\x00", 2) < 0:
        return "PKCS#1 padding has no terminator under this key"
    if _rsa_decrypt(ciphertext, modulus, exponent) is None:
        return "the recovered bytes are not ASCII under this key"
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
