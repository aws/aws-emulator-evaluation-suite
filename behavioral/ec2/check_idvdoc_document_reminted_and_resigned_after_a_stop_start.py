"""idvdoc-document-reminted-and-resigned-after-a-stop-start."""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import random
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "idvdoc-document-reminted-and-resigned-after-a-stop-start"
GROUP = 'idvdoc-identity'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
SSM_CORE_POLICY = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
SCENARIO = 'idvdoc-remint'
MARKER = 'SIM2REAL-IDVDOC'
#: pendingTime is stamped by the control plane, LaunchTime is reported by it; they describe the same
#: start and agree to the second in practice, so this only absorbs clock reporting skew.
PENDING_TIME_TOLERANCE_S = 120.0

#: The AWS RSA public certificate whose private key signs
#: /latest/dynamic/instance-identity/signature, transcribed verbatim from the EC2 User Guide
#: ("Use the base64-encoded signature to verify the instance identity document"). AWS publishes this
#: one for every commercial Region EXCEPT the opt-in Regions named in REGIONS_WITH_THEIR_OWN_CERT
#: below, which are each issued a different certificate. This is published AWS reference material,
#: not a fact about the account under test.
#:
#: Only the PUBLIC KEY is used, exactly as the AWS procedure does (`openssl x509 -pubkey -noout`),
#: so the certificate's own past validity dates are never consulted and do not matter.
AWS_RSA_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----
"""
#: Regions AWS issues a DIFFERENT identity-document certificate for.
REGIONS_WITH_THEIR_OWN_CERT = (
    "ap-east-1", "me-south-1", "me-central-1", "af-south-1", "eu-south-1", "eu-south-2",
    "eu-central-2", "ap-southeast-3", "ap-southeast-4", "ap-south-2",
)
REGION_PREFIXES_WITH_THEIR_OWN_CERT = ("cn-", "us-gov-")

THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: Fields the document must carry across a stop/start unchanged: they describe the instance, not
#: this boot of it.
INVARIANT_FIELDS = ("instanceId", "accountId", "region", "imageId", "instanceType",
                    "availabilityZone", "architecture", "version")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last observation: {last!r}"
    )


def _call_with_retry(fn, codes=THROTTLE, retries=75, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    """AZs that are BOTH available and offer the instance type, intersected rather than guessed."""
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    return usable


def _network(ctx, scenario, az):
    """A VPC of this check's own, with one public subnet, so nothing ambient is depended on."""
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-idvdoc-")}]
    second = random.randint(64, 191)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{second}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": kv}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    _poll_until(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
                lambda s: s == "available", ctx=ctx, timeout_s=_budget_s(ctx, 120), interval_s=2,
                description=f"vpc {vpc_id} reaches 'available'")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": kv}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_igw(ctx, igw_id, vpc_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rtb = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=f"10.{second}.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ctx, subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    return vpc_id, subnet_id


def _delete_subnet(ctx, subnet_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidSubnetID.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"subnet {subnet_id} was not deleted: {last!r}")


def _delete_igw(ctx, igw_id, vpc_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        except ClientError as exc:
            if _code(exc) not in ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"):
                last = exc
                time.sleep(2)
                continue
        try:
            _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidInternetGatewayID.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"internet gateway {igw_id} was not deleted: {last!r}")


def _delete_vpc(ctx, vpc_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVpcID.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"vpc {vpc_id} was not deleted: {last!r}")


def _instance_role(ctx, scenario):
    """An instance profile that lets the SSM agent register, created by this check and torn down."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-idvdoc-")
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description=f"sim2real {scenario} managed-instance role",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: _drop_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=SSM_CORE_POLICY)
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: _drop_instance_profile(ctx, role_name, role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    return role_name


def _drop_instance_profile(ctx, profile_name, role_name):
    iam = ctx.client("iam")
    for attempt in range(30):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 29:
                raise
            time.sleep(2)
    for attempt in range(30):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


def _drop_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    for attempt in range(30):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


def _run_instance(ctx, *, ami, subnet_id, profile_name, scenario,
                  instance_type=INSTANCE_TYPE):
    """Launch ONE instance, tagged in the same call that creates it."""
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-idvdoc-")}]
    return _call_with_retry(
        lambda: ctx.client("ec2").run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            MetadataOptions={"HttpEndpoint": "enabled", "HttpTokens": "required",
                             "HttpPutResponseHopLimit": 2},
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": kv},
                {"ResourceType": "volume", "Tags": kv},
            ],
        ),
        codes=THROTTLE + ("InvalidParameterValue",),
    )["Instances"][0]


def _instance_state(ctx, instance_id):
    ec2 = ctx.client("ec2")
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _describe_instance(ctx, instance_id):
    """DescribeInstances for one id, paginated so the instance is found on any page."""
    for page in ctx.client("ec2").get_paginator("describe_instances").paginate(
            InstanceIds=[instance_id]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    ec2 = ctx.client("ec2")
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = _instance_state(ctx, instance_id)
        if state in ("terminated", "__gone__"):
            return
        time.sleep(2)
    raise RuntimeError(f"instance {instance_id} was not terminated: still {state!r} after {timeout_s}s")


def _await_state(ctx, instance_id, wanted, timeout_s=360):
    return _poll_until(
        lambda: _instance_state(ctx, instance_id), lambda s: s == wanted,
        ctx=ctx, timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description=f"instance {instance_id} reaching {wanted!r}")


def _await_ssm_online(ctx, instance_id, timeout_s=420):
    ssm = ctx.client("ssm")

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll_until(
        _agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
        ctx=ctx, timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description=f"the SSM agent on {instance_id} coming Online")


def _guest_script():
    """Read the identity document and its signature FROM INSIDE the guest, byte-exactly."""
    return [
        "set -euo pipefail",
        'D=$(mktemp -d)',
        'curl -sS -f -X PUT "http://169.254.169.254/latest/api/token"'
        ' -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -o "$D/token"',
        'TOKEN=$(cat "$D/token")',
        'curl -sS -f -H "X-aws-ec2-metadata-token: $TOKEN"'
        ' http://169.254.169.254/latest/dynamic/instance-identity/document -o "$D/document"',
        'curl -sS -f -H "X-aws-ec2-metadata-token: $TOKEN"'
        ' http://169.254.169.254/latest/dynamic/instance-identity/signature -o "$D/signature"',
        f'echo "{MARKER} $(base64 -w0 "$D/document") $(base64 -w0 "$D/signature")'
        ' $(wc -c < "$D/token" | tr -d " ")"',
        'rm -rf "$D"',
    ]


def _read_identity_from_guest(ctx, instance_id, *, timeout_s=300):
    """Send the read to the guest and return (document bytes, signature bytes) it printed."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": _guest_script()},
        TimeoutSeconds=600,
        Comment=f"sim2real {SCENARIO}",
    ))
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll_until(
        _invocation, lambda i: i is not None and i.get("Status") in TERMINAL,
        ctx=ctx, timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description=f"invocation {command_id} on {instance_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"the guest read on {instance_id} was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"the guest read on {instance_id} exited {inv['ResponseCode']!r}, stderr="
        f"{inv.get('StandardErrorContent')!r}"
    )
    assert inv["StandardErrorContent"] == "", (
        f"the guest read wrote to stderr: {inv['StandardErrorContent']!r}"
    )
    stdout = inv["StandardOutputContent"]
    line = next((ln for ln in stdout.splitlines() if ln.startswith(MARKER)), None)
    assert line is not None, (
        f"the guest on {instance_id} never printed a {MARKER} line; its stdout was {stdout!r}"
    )
    fields = line.split()
    assert len(fields) == 4, (
        f"the {MARKER} line must carry the document, the signature and the token length, got "
        f"{fields!r}"
    )
    token_len = int(fields[3])
    assert token_len > 0, (
        f"the guest had to mint an IMDSv2 session token to read anything (HttpTokens=required), "
        f"but the token it received was {token_len} bytes"
    )
    return base64.b64decode(fields[1]), base64.b64decode(fields[2])


def _verify_rsa_signature(env, workdir, *, document, signature, label):
    """AWS's documented verification: extract the public key, then verify the RSA-SHA256 signature
    over the document bytes. Returns (returncode, combined output) — never a boolean, because this
    file asserts on BOTH outcomes."""
    cert = os.path.join(workdir, "certificate")
    key = os.path.join(workdir, f"key-{label}")
    doc = os.path.join(workdir, f"document-{label}")
    sig = os.path.join(workdir, f"signature-{label}")
    with open(cert, "w", encoding="ascii") as fh:
        fh.write(AWS_RSA_CERT_PEM)
    with open(doc, "wb") as fh:
        fh.write(document)
    with open(sig, "wb") as fh:
        fh.write(base64.b64decode(signature))
    pub = subprocess.run(["openssl", "x509", "-pubkey", "-noout", "-in", cert, "-out", key],
                         env=env, capture_output=True, text=True, timeout=60)
    assert pub.returncode == 0, (
        f"could not extract the public key from the published AWS certificate: {pub.stderr!r}"
    )
    done = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", key, "-signature", sig, doc],
        env=env, capture_output=True, text=True, timeout=60)
    return done.returncode, (done.stdout + done.stderr).strip()


def _pending_time(document, parsed):
    value = parsed.get("pendingTime")
    assert isinstance(value, str) and value, (
        f"the identity document must stamp the time this boot was started in pendingTime; got "
        f"{value!r} in {document!r}"
    )
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """After a stop/start the guest-read identity document has a new pendingTime matching LaunchTime,
    a fresh signature that verifies it (the old one must not), and unchanged instance fields.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    assert ctx.region not in REGIONS_WITH_THEIR_OWN_CERT and not ctx.region.startswith(
            REGION_PREFIXES_WITH_THEIR_OWN_CERT), (
        f"AWS publishes a different identity-document certificate for {ctx.region!r}, and this "
        f"check carries only the one it publishes for the other Regions, so verifying here would "
        f"assert nothing about the service; see the EC2 User Guide 'verify-signature'"
    )
    az = _usable_azs(ctx)[0]

    ec2 = ctx.client("ec2")
    ami = _ssm_ami(ctx)
    profile_name = _instance_role(ctx, SCENARIO)
    _vpc_id, subnet_id = _network(ctx, SCENARIO, az)

    launched = _run_instance(ctx, ami=ami, subnet_id=subnet_id, profile_name=profile_name,
                             scenario=SCENARIO)
    instance_id = launched["InstanceId"]
    # Registered immediately after the launch it undoes, before any assertion.
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))

    # --- boot 1: what the guest is served on its first start -----------------
    _await_state(ctx, instance_id, "running")
    _await_ssm_online(ctx, instance_id)
    first_doc, first_sig = _read_identity_from_guest(ctx, instance_id)
    first = json.loads(first_doc)
    first_launch = _describe_instance(ctx, instance_id)["LaunchTime"]
    assert first["instanceId"] == instance_id, (
        f"the document the guest read names {first['instanceId']!r}, not {instance_id!r}"
    )
    assert abs((_pending_time(first_doc, first) - first_launch).total_seconds()) \
        <= PENDING_TIME_TOLERANCE_S, (
        f"the document's pendingTime {first['pendingTime']!r} must describe the start "
        f"DescribeInstances reports as {first_launch.isoformat()}"
    )

    # Stop/start rather than reboot: a reboot does not restamp pendingTime.
    _call_with_retry(lambda: ec2.stop_instances(InstanceIds=[instance_id]))
    _await_state(ctx, instance_id, "stopped")
    _call_with_retry(lambda: ec2.start_instances(InstanceIds=[instance_id]))
    _await_state(ctx, instance_id, "running")
    _await_ssm_online(ctx, instance_id)

    # --- boot 2: what the guest is served now -------------------------------
    second_doc, second_sig = _read_identity_from_guest(ctx, instance_id)
    second = json.loads(second_doc)
    described = _describe_instance(ctx, instance_id)
    second_launch = described["LaunchTime"]

    with tempfile.TemporaryDirectory(prefix="sim2real-idvdoc-") as workdir:
        env = ctx.subprocess_env()

        # --- the positive control: each read's own pair verifies -------------
        for label, document, signature in (("boot1", first_doc, first_sig),
                                           ("boot2", second_doc, second_sig)):
            rc, output = _verify_rsa_signature(env, workdir, document=document,
                                               signature=signature, label=label)
            assert rc == 0 and "Verified OK" in output, (
                f"the document the guest read on {label} is not signed by the key in the AWS public "
                f"certificate for {ctx.region}: openssl exited {rc} with {output!r}"
            )

        # --- the document was re-minted, and its signature re-issued --------
        assert first_doc != second_doc, (
            f"the guest was served byte-identical identity documents before and after the "
            f"stop/start ({first_doc!r}); the document stamps the boot, so it must be re-minted"
        )
        assert first_sig != second_sig, (
            f"the signature was unchanged across the stop/start while the document changed; a "
            f"signature that does not follow its document cannot be verifying it"
        )
        rc, output = _verify_rsa_signature(env, workdir, document=second_doc,
                                           signature=first_sig, label="stale-sig")
        assert rc != 0 and "Verified OK" not in output, (
            f"the signature issued for the FIRST boot verified the SECOND boot's document (openssl "
            f"exited {rc}: {output!r}); the signature must cover the document that was re-minted"
        )

    # --- pendingTime advanced, and names the new start ----------------------
    first_pending = _pending_time(first_doc, first)
    second_pending = _pending_time(second_doc, second)
    assert second_launch > first_launch, (
        f"DescribeInstances reports LaunchTime {second_launch.isoformat()} after the restart, which "
        f"is not later than the first boot's {first_launch.isoformat()}; without a new start there "
        f"is nothing here to re-mint"
    )
    assert second_pending > first_pending, (
        f"the document's pendingTime did not advance across the stop/start: "
        f"{first['pendingTime']!r} then {second['pendingTime']!r}"
    )
    assert abs((second_pending - second_launch).total_seconds()) <= PENDING_TIME_TOLERANCE_S, (
        f"the re-minted document's pendingTime {second['pendingTime']!r} must describe the CURRENT "
        f"start, which DescribeInstances reports as {second_launch.isoformat()}"
    )

    # --- everything that describes the instance is unchanged ----------------
    for field in INVARIANT_FIELDS:
        assert first[field] == second[field], (
            f"the identity document's {field!r} changed across a stop/start of the same instance: "
            f"{first[field]!r} then {second[field]!r}"
        )
    assert second["instanceId"] == described["InstanceId"], (
        f"the re-minted document names {second['instanceId']!r}; the control plane calls this "
        f"instance {described['InstanceId']!r}"
    )
    assert second["instanceType"] == described["InstanceType"], (
        f"the re-minted document reports instanceType {second['instanceType']!r}, the control plane "
        f"reports {described['InstanceType']!r}"
    )
    assert second["imageId"] == described["ImageId"], (
        f"the re-minted document reports imageId {second['imageId']!r}, the control plane reports "
        f"{described['ImageId']!r}"
    )
    assert second["availabilityZone"] == described["Placement"]["AvailabilityZone"], (
        f"the re-minted document places the instance in {second['availabilityZone']!r}, the control "
        f"plane in {described['Placement']['AvailabilityZone']!r}"
    )
    assert second["privateIp"] == described["PrivateIpAddress"], (
        f"the re-minted document reports privateIp {second['privateIp']!r}, the control plane "
        f"reports {described['PrivateIpAddress']!r}"
    )
    assert second["accountId"] == ctx.client("sts").get_caller_identity()["Account"], (
        f"the re-minted document attests account {second['accountId']!r}, which is not the account "
        f"that owns the instance"
    )
    assert second["region"] == ctx.region, (
        f"the re-minted document attests region {second['region']!r}, not {ctx.region!r}"
    )


# AWS-managed ENIs of resources deleted asynchronously keep a subnet/SG/VPC delete failing with
# DependencyViolation for a while, so teardown waits (bounded) for them and retries.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
