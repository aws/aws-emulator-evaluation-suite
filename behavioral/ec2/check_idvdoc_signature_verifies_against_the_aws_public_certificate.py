"""idvdoc-signature-verifies-against-the-aws-public-certificate."""
from __future__ import annotations

import base64
import json
import os
import random
import subprocess
import tempfile
import time
from datetime import timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "idvdoc-signature-verifies-against-the-aws-public-certificate"
GROUP = 'idvdoc-identity'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
SSM_CORE_POLICY = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
SCENARIO = 'idvdoc-signature'
MARKER = 'SIM2REAL-IDVDOC'
#: The document's own report of when the instance entered `pending` must agree with the launch time
#: the control plane reports. Both come from AWS, so the tolerance only absorbs their rounding.
PENDING_TIME_TOLERANCE_S = 120.0

#: The AWS RSA public certificate whose private key signs
#: /latest/dynamic/instance-identity/signature, transcribed verbatim from the EC2 User Guide
#: ("Use the base64-encoded signature to verify the instance identity document"). AWS publishes this
#: one for every commercial Region EXCEPT the opt-in Regions named in REGIONS_WITH_THEIR_OWN_CERT
#: below, which are each issued a different certificate. This is published AWS reference material,
#: not a fact about the account under test: nothing here is read from, or true only of, this account.
#:
#: The certificate's own validity dates are in the past. That is irrelevant and deliberate — only the
#: PUBLIC KEY is used, exactly as the AWS procedure does (`openssl x509 -pubkey -noout`), so no chain
#: or expiry is ever consulted. What is asserted is an RSA signature, and a signature either verifies
#: under that key or it does not.
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
#: Regions AWS issues a DIFFERENT identity-document certificate for. Verifying in one of these with
#: the certificate above would be a false negative about the service, so the check says so instead.
REGIONS_WITH_THEIR_OWN_CERT = (
    "ap-east-1", "me-south-1", "me-central-1", "af-south-1", "eu-south-1", "eu-south-2",
    "eu-central-2", "ap-southeast-3", "ap-southeast-4", "ap-south-2",
)
REGION_PREFIXES_WITH_THEIR_OWN_CERT = ("cn-", "us-gov-")

THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

# ===== helpers (self-contained) =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last observation: {last!r}"
    )


def _call_with_retry(fn, codes=THROTTLE, retries=30, delay=5.0):
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
    """AZs that are BOTH available and offer the instance type, intersected rather than guessed.

    describe_instance_type_offerings reports no zone state and describe_availability_zones reports
    no instance types, so either alone picks a zone that cannot run the check.
    """
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


def _network(ctx, scenario, azs):
    """A VPC of this check's own, with one subnet per requested AZ and egress to the internet.

    Nothing ambient: a fresh account may have no default VPC. The
    CIDR is random in 10/8 because overlapping VPC CIDRs are legal (these VPCs are never peered), so
    a sibling run in the same account cannot collide. Egress exists because the SSM agent has to
    reach the SSM endpoint to register before any command can be sent to the guest at all.
    """
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
                lambda s: s == "available", timeout_s=120, interval_s=3,
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

    subnets = {}
    for i, az in enumerate(azs, start=1):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.{second}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _delete_subnet(ctx, s))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        subnets[az] = subnet_id
    return vpc_id, subnets


def _delete_subnet(ctx, subnet_id):
    """`_delete_net` retries DependencyViolation; only the subnet's own not-found counts as done."""
    try:
        _delete_net(ctx.client("ec2"), "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if _code(exc) != "InvalidSubnetID.NotFound":
            raise


def _delete_igw(ctx, igw_id, vpc_id):
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) not in ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"):
            raise
    try:
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
    except ClientError as exc:
        if _code(exc) != "InvalidInternetGatewayID.NotFound":
            raise


def _delete_vpc(ctx, vpc_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) != "InvalidVpcID.NotFound":
            raise


def _instance_role(ctx, scenario):
    """An instance profile that lets the SSM agent register, created by this check and torn down.

    Nothing ambient: there is no account-wide default instance profile to borrow, and borrowing one
    would make the check assert this account's configuration rather than the service's behaviour.
    """
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
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _run_instance(ctx, *, ami, subnet_id, profile_name, scenario,
                  instance_type=INSTANCE_TYPE):
    """Launch ONE instance, tagged in the same call that creates it.

    An instance tagged in a follow-up call that an abort can skip would be left untagged. A
    brand-new instance profile is not immediately resolvable by RunInstances, hence the bounded
    retry.
    """
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-idvdoc-")}]
    return _call_with_retry(
        lambda: ctx.client("ec2").run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            # HttpTokens=required, so the guest's read below can only succeed through an IMDSv2
            # session. The identity document is credential-adjacent material and this is how a
            # customer is told to expose it.
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
    """DescribeInstances for one id, PAGINATED — the account is shared and pages are not ours alone."""
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
    while time.monotonic() < deadline:
        if _instance_state(ctx, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _await_ssm_online(ctx, instance_id, timeout_s=600):
    ssm = ctx.client("ssm")

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll_until(
        _agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=timeout_s, interval_s=5.0,
        description=f"the SSM agent on {instance_id} coming Online")


def _guest_script():
    """Read the identity document and its signature FROM INSIDE the guest, byte-exactly.

    Every field is emitted base64 so nothing the shell does to newlines can alter the bytes that
    were signed: `$(curl ...)` strips trailing newlines, and a signature is over bytes, not over a
    JSON value. Each fetch is `curl -f`, so a metadata endpoint that answers with an HTTP error is a
    non-zero ResponseCode rather than an empty field that reads like a parse problem.
    """
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


def _send_and_collect(ctx, instance_ids, script, *, timeout_s=300):
    """Run one shell script on each instance and return {instance_id: invocation}."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=list(instance_ids),
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": script},
        TimeoutSeconds=600,
        Comment=f"sim2real {SCENARIO}",
    ))
    command_id = sent["Command"]["CommandId"]
    out = {}
    for instance_id in instance_ids:
        def _invocation(i=instance_id):
            try:
                return ssm.get_command_invocation(CommandId=command_id, InstanceId=i)
            except ClientError as exc:
                if _code(exc) == "InvocationDoesNotExist":
                    return None
                raise

        out[instance_id] = _poll_until(
            _invocation, lambda inv: inv is not None and inv.get("Status") in TERMINAL,
            timeout_s=timeout_s, interval_s=5.0,
            description=f"invocation of {command_id} on {instance_id} reaching a terminal status")
    return command_id, out


def _guest_material(inv, instance_id):
    """The (document bytes, signature bytes, token length) the GUEST printed.

    Raises with the invocation's own diagnostics rather than an IndexError, because a command that
    ran and printed nothing is the interesting failure.
    """
    assert inv["Status"] == "Success", (
        f"the guest command on {instance_id} was {inv['Status']!r}: "
        f"{inv.get('StatusDetails')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"the guest command on {instance_id} exited {inv['ResponseCode']!r}, stderr="
        f"{inv.get('StandardErrorContent')!r}"
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
    return base64.b64decode(fields[1]), base64.b64decode(fields[2]), int(fields[3])


def _verify_rsa_signature(env, workdir, *, document, signature_b64, label):
    """AWS's own documented verification: extract the public key, then verify the RSA-SHA256
    signature over the document bytes. Returns (returncode, combined output).

    Not a boolean, because the caller asserts on BOTH outcomes: a verification that succeeds when it
    must and one that fails when the bytes are altered. `openssl` is a tool the runner guarantees, so
    a missing binary is a run defect rather than a silent branch.
    """
    cert = os.path.join(workdir, "certificate")
    key = os.path.join(workdir, f"key-{label}")
    doc = os.path.join(workdir, f"document-{label}")
    sig = os.path.join(workdir, f"signature-{label}")
    with open(cert, "w", encoding="ascii") as fh:
        fh.write(AWS_RSA_CERT_PEM)
    with open(doc, "wb") as fh:
        fh.write(document)
    with open(sig, "wb") as fh:
        fh.write(base64.b64decode(signature_b64))
    pub = subprocess.run(["openssl", "x509", "-pubkey", "-noout", "-in", cert, "-out", key],
                         env=env, capture_output=True, text=True, timeout=60)
    assert pub.returncode == 0, (
        f"could not extract the public key from the published AWS certificate: {pub.stderr!r}"
    )
    done = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", key, "-signature", sig, doc],
        env=env, capture_output=True, text=True, timeout=60)
    return done.returncode, (done.stdout + done.stderr).strip()


# ===== end helpers =====


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
    """The identity document a guest reads from IMDS verifies under its RSA-SHA256 signature and the
    Region's published AWS certificate, a one-byte-altered copy fails, and every field equals what
    the control plane reports: it is the only cryptographic identity an instance has."""
    from fidelity_tests_runner import require_tools

    # Every decidable precondition ahead of the first create: an instance billed for an answer that
    # was available at import time is pure waste.
    require_tools("openssl")
    assert ctx.region not in REGIONS_WITH_THEIR_OWN_CERT and not ctx.region.startswith(
            REGION_PREFIXES_WITH_THEIR_OWN_CERT), (
        f"AWS publishes a different identity-document certificate for {ctx.region!r}, and this "
        f"check carries only the one it publishes for the other Regions, so verifying here would "
        f"assert nothing about the service; see the EC2 User Guide 'verify-signature'"
    )
    az = _usable_azs(ctx)[0]

    account = ctx.client("sts").get_caller_identity()["Account"]
    ami = _ssm_ami(ctx)
    profile_name = _instance_role(ctx, SCENARIO)
    _vpc_id, subnets = _network(ctx, SCENARIO, [az])

    launched = _run_instance(ctx, ami=ami, subnet_id=subnets[az], profile_name=profile_name,
                             scenario=SCENARIO)
    instance_id = launched["InstanceId"]
    # Registered immediately, before the next assertion: an instance that never registers with SSM
    # must be terminated rather than left billing.
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    assert launched["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {launched['Placement']!r}, not the derived zone {az!r}"
    )

    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance {instance_id} reaches 'running'")
    _await_ssm_online(ctx, instance_id)

    # --- the guest reads its own identity document and signature -------------
    command_id, invocations = _send_and_collect(ctx, [instance_id], _guest_script())
    inv = invocations[instance_id]
    assert inv["InstanceId"] == instance_id, (
        f"invocation {command_id} reports instance {inv['InstanceId']!r}, expected {instance_id!r}"
    )
    document, signature_b64, token_len = _guest_material(inv, instance_id)
    assert token_len > 0, (
        f"the guest had to mint an IMDSv2 session token to read anything (HttpTokens=required), "
        f"but the token it received was {token_len} bytes"
    )
    assert inv["StandardErrorContent"] == "", (
        f"the guest script wrote to stderr: {inv['StandardErrorContent']!r}"
    )

    # --- the signature verifies under the published AWS public key -----------
    with tempfile.TemporaryDirectory(prefix="sim2real-idvdoc-") as workdir:
        env = ctx.subprocess_env()
        rc, output = _verify_rsa_signature(env, workdir, document=document,
                                           signature_b64=signature_b64, label="genuine")
        assert rc == 0, (
            f"the instance identity document served to {instance_id} inside the guest is not signed "
            f"by the key in the AWS public certificate for {ctx.region}: openssl exited {rc} with "
            f"{output!r}. The document was {document!r}"
        )
        assert "Verified OK" in output, (
            f"openssl exited 0 but did not report a verified signature: {output!r}"
        )

        # The control that makes the line above falsifiable: the SAME verification over the SAME
        # document with one identifier byte altered must fail.
        altered = instance_id[:-1] + ("0" if instance_id[-1] != "0" else "1")
        tampered = document.replace(instance_id.encode(), altered.encode())
        assert tampered != document, (
            f"the tamper control could not alter the document: {instance_id!r} does not appear in "
            f"{document!r}"
        )
        bad_rc, bad_output = _verify_rsa_signature(env, workdir, document=tampered,
                                                   signature_b64=signature_b64, label="tampered")
        assert bad_rc != 0, (
            f"a document whose instanceId was changed from {instance_id!r} to {altered!r} still "
            f"verified under AWS's public key (openssl exited {bad_rc}: {bad_output!r}) — the "
            f"signature is not bound to the document's bytes"
        )
        assert "Verified OK" not in bad_output, (
            f"the tampered document was reported as verified: {bad_output!r}"
        )

    # --- and the signed document describes THIS instance ---------------------
    parsed = json.loads(document)
    described = _describe_instance(ctx, instance_id)
    expected = {
        "instanceId": instance_id,
        "accountId": account,
        "region": ctx.region,
        "imageId": described["ImageId"],
        "instanceType": described["InstanceType"],
        "availabilityZone": described["Placement"]["AvailabilityZone"],
        "privateIp": described["PrivateIpAddress"],
        "architecture": described["Architecture"],
    }
    for field, want in expected.items():
        assert parsed.get(field) == want, (
            f"the signed identity document reports {field}={parsed.get(field)!r}, but the control "
            f"plane reports {want!r} for the same instance; the whole document was {parsed!r}"
        )
    assert parsed["instanceType"] == INSTANCE_TYPE, (
        f"this check launched a {INSTANCE_TYPE!r} and the document must say so, got "
        f"{parsed['instanceType']!r}"
    )
    assert parsed.get("imageId") == ami, (
        f"the document names image {parsed.get('imageId')!r}, but this check launched {ami!r}"
    )

    # pendingTime is the document's own account of when the instance started, and the control plane
    # reports the same moment through a different field. Compared with a tolerance because both are
    # AWS's own clocks, never as a wall-clock deadline on the check.
    pending = parsed.get("pendingTime")
    assert isinstance(pending, str) and pending.endswith("Z"), (
        f"the document must timestamp the launch in UTC, got pendingTime={pending!r}"
    )
    pending_epoch = time.mktime(time.strptime(pending, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    launch_epoch = described["LaunchTime"].astimezone(timezone.utc).timestamp()
    assert abs(pending_epoch - launch_epoch) <= PENDING_TIME_TOLERANCE_S, (
        f"the signed document says the instance entered pending at {pending!r} but the control "
        f"plane reports LaunchTime {described['LaunchTime']!r}; they differ by "
        f"{abs(pending_epoch - launch_epoch):.0f}s"
    )
    assert parsed.get("version"), (
        f"the identity document must declare its own schema version, got {parsed!r}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A resource in this
# VPC deletes asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation while its ENIs remain: retry that code inside one window shared by the
# check's network deletes, then raise naming the ENIs still attached. Teardown-only.
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
