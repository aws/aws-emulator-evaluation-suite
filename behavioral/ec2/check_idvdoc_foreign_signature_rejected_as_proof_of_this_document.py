"""idvdoc-foreign-signature-rejected-as-proof-of-this-document."""
from __future__ import annotations

import base64
import json
import os
import random
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "idvdoc-foreign-signature-rejected-as-proof-of-this-document"
GROUP = 'idvdoc-identity'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
SSM_CORE_POLICY = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
SCENARIO = 'idvdoc-foreign-signature'
MARKER = 'SIM2REAL-IDVDOC'

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


def _network(ctx, scenario, azs):
    """A VPC of this check's own, with one subnet per requested AZ and egress to the internet."""
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
    """DescribeInstances for one id, paginated so the match is found on any page."""
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


def _await_running(ctx, instance_ids, timeout_s=420):
    """Poll both instances together so the worst case is one 'running' wait, not two in series."""
    wanted = sorted(set(instance_ids))

    def _states():
        return {i: _instance_state(ctx, i) for i in wanted}

    return _poll_until(
        _states, lambda s: all(v == "running" for v in s.values()),
        timeout_s=timeout_s, interval_s=5.0,
        description=f"instances {wanted!r} all reaching 'running'")


def _await_ssm_online(ctx, instance_ids, timeout_s=600):
    """Wait for every agent to register, polled together for the same reason."""
    ssm = ctx.client("ssm")
    wanted = set(instance_ids)

    def _agent_view():
        seen = {}
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") in wanted:
                    seen[info["InstanceId"]] = info.get("PingStatus")
        return seen

    return _poll_until(
        _agent_view,
        lambda seen: set(seen) == wanted and all(v == "Online" for v in seen.values()),
        timeout_s=timeout_s, interval_s=5.0,
        description=f"the SSM agents on {sorted(wanted)!r} all coming Online")


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


def _send_and_collect(ctx, instance_ids, script, *, timeout_s=300):
    """Run one shell script on each instance and return (command_id, {instance_id: invocation})."""
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
    """The (document bytes, signature bytes, token length) the GUEST printed."""
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
    """AWS's documented verification: extract the public key, verify RSA-SHA256 over the document.

    Returns (returncode, combined output), since callers assert on both outcomes."""
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Each of two instances' identity signatures verifies its own document but not the other's.

    The documents and signatures must also differ, so one canned pair served to both cannot pass.

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

    ami = _ssm_ami(ctx)
    profile_name = _instance_role(ctx, SCENARIO)
    _vpc_id, subnets = _network(ctx, SCENARIO, [az])

    # --- two instances, launched separately so each gets its own identity ----
    instance_ids = []
    for _ in range(2):
        launched = _run_instance(ctx, ami=ami, subnet_id=subnets[az],
                                 profile_name=profile_name, scenario=SCENARIO)
        instance_id = launched["InstanceId"]
        # Registered immediately after the launch it undoes, before the next launch: a second
        # RunInstances that fails must not be able to strand the first instance.
        ctx.on_cleanup(lambda i=instance_id: _terminate_and_wait(ctx, i))
        instance_ids.append(instance_id)
    first, second = instance_ids
    assert first != second, (
        f"two RunInstances calls returned the same instance id {first!r}"
    )

    _await_running(ctx, instance_ids)
    _await_ssm_online(ctx, instance_ids)

    # --- each guest reads its OWN identity document and signature ------------
    command_id, invocations = _send_and_collect(ctx, instance_ids, _guest_script())
    material = {}
    for instance_id in instance_ids:
        inv = invocations[instance_id]
        assert inv["InstanceId"] == instance_id, (
            f"invocation {command_id} reports instance {inv['InstanceId']!r}, expected "
            f"{instance_id!r}"
        )
        document, signature_b64, token_len = _guest_material(inv, instance_id)
        assert token_len > 0, (
            f"the guest on {instance_id} had to mint an IMDSv2 session token to read anything "
            f"(HttpTokens=required), but the token it received was {token_len} bytes"
        )
        material[instance_id] = (document, signature_b64)

    doc_first, sig_first = material[first]
    doc_second, sig_second = material[second]

    # --- the two identities are genuinely distinct ---------------------------
    parsed_first = json.loads(doc_first)
    parsed_second = json.loads(doc_second)
    assert parsed_first["instanceId"] == first, (
        f"the document the guest on {first} printed names {parsed_first['instanceId']!r}; each "
        f"instance must be served its own identity"
    )
    assert parsed_second["instanceId"] == second, (
        f"the document the guest on {second} printed names {parsed_second['instanceId']!r}; each "
        f"instance must be served its own identity"
    )
    assert doc_first != doc_second, (
        f"both guests were served byte-identical identity documents ({doc_first!r}); an identity "
        f"document that does not distinguish two instances attests to nothing"
    )
    assert sig_first != sig_second, (
        f"both guests were served the same signature blob ({sig_first!r}); a signature reused "
        f"across instances is not a per-instance attestation"
    )

    with tempfile.TemporaryDirectory(prefix="sim2real-idvdoc-") as workdir:
        env = ctx.subprocess_env()

        # --- the positive control, in this file, before the substitution -----
        for label, instance_id, document, signature_b64 in (
                ("own-first", first, doc_first, sig_first),
                ("own-second", second, doc_second, sig_second)):
            rc, output = _verify_rsa_signature(env, workdir, document=document,
                                               signature_b64=signature_b64, label=label)
            assert rc == 0, (
                f"the identity document the guest on {instance_id} read is not signed by the key in "
                f"the AWS public certificate for {ctx.region}: openssl exited {rc} with {output!r}"
            )
            assert "Verified OK" in output, (
                f"openssl exited 0 for {instance_id} but did not report a verified signature: "
                f"{output!r}"
            )

        # --- break exactly one thing: offer the OTHER instance's signature ---
        for label, doc_owner, sig_owner, document, signature_b64 in (
                ("cross-second-sig-first-doc", first, second, doc_first, sig_second),
                ("cross-first-sig-second-doc", second, first, doc_second, sig_first)):
            rc, output = _verify_rsa_signature(env, workdir, document=document,
                                               signature_b64=signature_b64, label=label)
            assert rc != 0, (
                f"the signature AWS issued to {sig_owner} verified {doc_owner}'s identity document "
                f"(openssl exited {rc}: {output!r}) — one instance's attestation must not prove "
                f"another's identity"
            )
            assert "Verified OK" not in output, (
                f"{sig_owner}'s signature was reported as verifying {doc_owner}'s document: "
                f"{output!r}"
            )

        # --- and the genuine pairing still verifies AFTER the substitution ---
        # The same positive, re-run last, so the failures above cannot be explained by anything the
        # verification attempts left behind.
        rc, output = _verify_rsa_signature(env, workdir, document=doc_first,
                                          signature_b64=sig_first, label="own-first-again")
        assert rc == 0 and "Verified OK" in output, (
            f"{first}'s own document stopped verifying after the substitution attempts: openssl "
            f"exited {rc} with {output!r}"
        )

    # --- the control plane agrees that these are two live instances ----------
    for instance_id in instance_ids:
        described = _describe_instance(ctx, instance_id)
        assert described["State"]["Name"] == "running", (
            f"instance {instance_id} is {described['State']!r}; both instances must still be "
            f"running for the comparison above to be about two live identities"
        )
        assert json.loads(material[instance_id][0])["privateIp"] == \
            described["PrivateIpAddress"], (
            f"the signed document for {instance_id} reports privateIp "
            f"{json.loads(material[instance_id][0])['privateIp']!r}, the control plane reports "
            f"{described['PrivateIpAddress']!r}"
        )


# AWS-managed ENIs leave a VPC asynchronously after their owner is deleted, so an immediate
# DeleteSubnet / DeleteVpc fails with DependencyViolation. Wait (bounded, shared by all network
# deletes of one check) for the ENIs to go, then raise naming any still attached.
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
