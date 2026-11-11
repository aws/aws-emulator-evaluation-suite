"""instance-profile-role-swap-changes-the-credentials-imds-serves."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "instance-profile-role-swap-changes-the-credentials-imds-serves"
GROUP = 'identity'
SERVICES = ['ec2', 'iam']

_INSTANCE_RUNNING_TIMEOUT_S = 300.0
_AGENT_ONLINE_TIMEOUT_S = 420.0
_COMMAND_TIMEOUT_S = 180.0
_IMDS_ROLE_SWAP_TIMEOUT_S = 600.0
_TEARDOWN_TIMEOUT_S = 300.0

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.85.0.0/16"
_SUBNET_CIDR = "10.85.1.0/24"

_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE = ("InvalidInstanceID.NotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
         "InvalidGroup.NotFound", "InvalidInternetGatewayID.NotFound", "NoSuchEntity")

#: One prefix per role. Each role may write to exactly its own, so the two verdicts must INVERT
#: when the profile's role is swapped.
_PREFIX_A = "role-a"
_PREFIX_B = "role-b"


def _cli_error(err: str) -> tuple[str, str]:
    """(code, message) from the AWS CLI's error report on stderr:
    ``[aws: [ERROR]: ]An error occurred (<Code>) when calling the <Op> operation: <Message>``."""
    line = err.strip()
    head = "An error occurred ("
    at = line.find(head)
    assert at >= 0, f"the CLI did not report a service error; stderr={err!r}"
    code, _, rest = line[at + len(head):].partition(")")
    _, _, message = rest.partition(" operation: ")
    return code, message


def _no_identity_policy_message(account: str, role: str, instance_id: str, object_path: str) -> str:
    """S3's AccessDenied message for an instance-profile session whose role grants no PutObject."""
    session = f"arn:aws:sts::{account}:assumed-role/{role}/{instance_id}"
    return (f"User: {session} is not authorized to perform: s3:PutObject on resource: "
            f"\"arn:aws:s3:::{object_path}\" because no identity-based policy allows the "
            f"s3:PutObject action")


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Bounded retry that RAISES on timeout. Never a bare sleep."""
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


def _tags(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "imds-instance-profile-swap"}]


def _instance_states(ec2, instance_id: str) -> list[str]:
    """DescribeInstances states for instance_id; [] while the id is briefly NotFound.

    DescribeInstances can answer InvalidInstanceID.NotFound for a few seconds right after
    RunInstances or termination; that is treated as "no state observed yet".
    """
    try:
        return [i["State"]["Name"]
                for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
                for i in r["Instances"]]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return []
        raise


def _usable_zone(ec2, region: str) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in {region} offers {_INSTANCE_TYPE}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    return usable[0]


def _build_network(ec2, region: str, name: str, st: dict) -> None:
    """A VPC with one public subnet so the SSM agent can register; every id in *st* is made here."""
    st["vpc"] = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags(name)}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[st["vpc"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsHostnames={"Value": True})

    st["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"])

    main_rt = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["RouteTables"]
    assert len(main_rt) == 1, (
        f"a freshly created VPC must have exactly one (main) route table; got "
        f"{[r['RouteTableId'] for r in main_rt]!r}"
    )
    ec2.create_route(RouteTableId=main_rt[0]["RouteTableId"],
                     DestinationCidrBlock="0.0.0.0/0", GatewayId=st["igw"])

    st["subnet"] = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=_usable_zone(ec2, region),
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(name)}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=st["subnet"], MapPublicIpOnLaunch={"Value": True})

    sgs = [g["GroupId"] for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["SecurityGroups"]
        if g["GroupName"] == "default"]
    assert len(sgs) == 1, (
        f"the created VPC must have exactly one default security group; got {sgs!r}"
    )
    st["sg"] = sgs[0]


def _prefix_role(iam, name: str, bucket: str, prefix: str) -> str:
    """A role trusting EC2, able to register with SSM and to write to exactly one S3 prefix."""
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description=f"sim2real-behav imds swap, scoped to {prefix}/",
        Tags=[{"Key": "sim2real", "Value": "imds-instance-profile-swap"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
    iam.put_role_policy(
        RoleName=name, PolicyName="one-prefix",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/{prefix}/*",
            }],
        }),
    )
    return arn


def _probe_script(region: str, bucket: str, marker: str) -> list[str]:
    """One JSON line on stdout describing what IMDS served and what those credentials could do.

    Key material never leaves the host (AccessKeyId as a SHA-256 prefix, secret/token as booleans).
    Embedded Python uses heredocs: inside shell single quotes `\\n` would not be a newline.
    """
    return [
        "set -uo pipefail",
        "IMDS=http://169.254.169.254",
        f"REG={region}",
        f"B={bucket}",
        f"M={marker}",
        'T=$(curl -sS -X PUT "$IMDS/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")',
        'H="X-aws-ec2-metadata-token: $T"',
        'ROLE=$(curl -sS -H "$H" "$IMDS/latest/meta-data/iam/security-credentials/" '
        '| head -n1 || true)',
        'curl -sS -H "$H" "$IMDS/latest/meta-data/iam/security-credentials/$ROLE" '
        '> /tmp/doc.json 2>/dev/null || true',
        'curl -sS -H "$H" "$IMDS/latest/meta-data/iam/info" > /tmp/info.json 2>/dev/null || true',
        # --- sign with what the endpoint served, explicitly ---
        "python3 - > /tmp/exports.sh <<'PYEXP'",
        "import json",
        "try:",
        '    d = json.load(open("/tmp/doc.json"))',
        "except (OSError, ValueError):",
        "    raise SystemExit(0)",
        'print("export AWS_ACCESS_KEY_ID=%s" % d["AccessKeyId"])',
        'print("export AWS_SECRET_ACCESS_KEY=%s" % d["SecretAccessKey"])',
        'print("export AWS_SESSION_TOKEN=%s" % d["Token"])',
        "PYEXP",
        '. /tmp/exports.sh',
        f'aws s3api put-object --bucket "$B" --key {_PREFIX_A}/"$M" --region "$REG" '
        '> /dev/null 2>/tmp/a.err; ARC=$?',
        f'aws s3api put-object --bucket "$B" --key {_PREFIX_B}/"$M" --region "$REG" '
        '> /dev/null 2>/tmp/b.err; BRC=$?',
        'rm -f /tmp/exports.sh',
        # --- the single JSON summary line ---
        'export ROLE ARC BRC M',
        "python3 - <<'PYSUM'",
        "import json, os, hashlib",
        "",
        "",
        "def load(path):",
        "    try:",
        "        return json.load(open(path))",
        "    except (OSError, ValueError):",
        "        return {}",
        "",
        "",
        "def text(path):",
        "    try:",
        "        return open(path).read()[:2000]",
        "    except OSError:",
        '        return ""',
        "",
        "",
        'doc = load("/tmp/doc.json")',
        'info = load("/tmp/info.json")',
        'akid = doc.get("AccessKeyId", "")',
        "print(json.dumps({",
        '    "marker": os.environ.get("M", ""),',
        '    "listed_role": os.environ.get("ROLE", "").strip(),',
        '    "code": doc.get("Code", ""),',
        '    "cred_type": doc.get("Type", ""),',
        '    "akid_prefix": akid[:4],',
        '    "akid_sha": hashlib.sha256(akid.encode()).hexdigest()[:16] if akid else "",',
        '    "has_secret": bool(doc.get("SecretAccessKey")),',
        '    "has_token": bool(doc.get("Token")),',
        '    "expiration": doc.get("Expiration", ""),',
        '    "info_profile_arn": info.get("InstanceProfileArn", ""),',
        '    "a_rc": int(os.environ.get("ARC", "-1")), "a_err": text("/tmp/a.err"),',
        '    "b_rc": int(os.environ.get("BRC", "-1")), "b_err": text("/tmp/b.err"),',
        "}))",
        "PYSUM",
    ]


def _run_probe(ssm, instance_id: str, script: list[str]) -> dict:
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": script}, TimeoutSeconds=int(_COMMAND_TIMEOUT_S),
        Comment="sim2real-behav imds instance-profile probe"))
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=_COMMAND_TIMEOUT_S,
                what=f"invocation {command_id} on {instance_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"the probe script must run to completion (a denied PutObject does not fail it, because "
        f"the rc is captured); SSM reports {inv['Status']!r}, "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip().startswith("{")]
    assert lines, (
        f"the probe printed no JSON line; stdout={inv['StandardOutputContent']!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return json.loads(lines[-1])


def _s3_head_code(s3, bucket: str, key: str) -> str:
    """The code HeadObject answers with. RAISES if the object exists."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code"))
    raise AssertionError(
        f"s3://{bucket}/{key} was expected not to exist and HeadObject found it")


def _wait_gone(ec2, instance_id: str) -> None:
    _poll(
        lambda: _instance_states(ec2, instance_id),
        lambda states: all(s in ("shutting-down", "terminated") for s in states),
        timeout_s=_TEARDOWN_TIMEOUT_S,
        what=f"instance {instance_id} leaving running",
    )


def _teardown(ec2, iam, st: dict) -> None:
    """Ordered, waiting teardown, in band. Runs every step, then raises naming each one that
    failed on anything but an already-gone code.
    """
    left: list[str] = []
    steps: list = []

    def _try(label: str, fn) -> None:
        steps.append((label, fn))

    if st.get("instance"):
        _try("terminate", lambda: ec2.terminate_instances(InstanceIds=[st["instance"]]))
        _try("await-terminated", lambda: _wait_gone(ec2, st["instance"]))
    if st.get("subnet"):
        _try("await-eni-drain", lambda: _poll(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [st["subnet"]]}])["NetworkInterfaces"],
            lambda enis: not enis,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            what=f"subnet {st['subnet']} draining its ENIs"))
    for profile in st.get("profiles", []):
        role = st.get("profile_roles", {}).get(profile)
        if role:
            _try(f"remove-{role}-from-{profile}",
                 lambda p=profile, r=role: iam.remove_role_from_instance_profile(
                     InstanceProfileName=p, RoleName=r))
        _try(f"delete-instance-profile-{profile}",
             lambda p=profile: iam.delete_instance_profile(InstanceProfileName=p))
    for role in st.get("roles", []):
        _try(f"delete-{role}-policy",
             lambda r=role: iam.delete_role_policy(RoleName=r, PolicyName="one-prefix"))
        _try(f"detach-{role}-ssm-core",
             lambda r=role: iam.detach_role_policy(RoleName=r, PolicyArn=_SSM_CORE_POLICY))
        _try(f"delete-role-{role}", lambda r=role: iam.delete_role(RoleName=r))
    if st.get("subnet"):
        _try("delete-subnet", lambda: ec2.delete_subnet(SubnetId=st["subnet"]))
    if st.get("igw"):
        _try("detach-igw", lambda: ec2.detach_internet_gateway(
            InternetGatewayId=st["igw"], VpcId=st["vpc"]))
        _try("delete-igw", lambda: ec2.delete_internet_gateway(
            InternetGatewayId=st["igw"]))
    if st.get("vpc"):
        _try("delete-vpc", lambda: ec2.delete_vpc(VpcId=st["vpc"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                left.append(f"{label}: {exc.response.get('Error', {}).get('Code')}")
        except (AssertionError, WaiterError) as exc:
            left.append(f"{label}: {type(exc).__name__}: {str(exc)[:120]}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


@tags("axis:rejection", "cap:c7", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """IMDS serves the instance profile role's credentials, calls signed with them are bounded by
    that role, and replacing the running instance's profile association changes the listed role
    and served credentials, inverting which S3 prefix the instance may write.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stem = ctx.unique_name("sim2real-behav-imds-")
    st: dict = {"roles": [], "profiles": []}

    bucket = stem
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    def _empty_and_delete_bucket() -> None:
        # DeleteBucket requires an empty bucket, and pre-swap poll attempts leave extra objects.
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "imds-instance-profile-swap"}]})

    try:
        _build_network(ec2, ctx.region, stem, st)

        role_a, role_b = f"{stem}-a", f"{stem}-b"
        _prefix_role(iam, role_a, bucket, _PREFIX_A)
        st["roles"].append(role_a)
        _prefix_role(iam, role_b, bucket, _PREFIX_B)
        st["roles"].append(role_b)

        profile_a, profile_b = f"{stem}-prof-a", f"{stem}-prof-b"
        for profile, role in ((profile_a, role_a), (profile_b, role_b)):
            iam.create_instance_profile(
                InstanceProfileName=profile,
                Tags=[{"Key": "sim2real", "Value": "imds-instance-profile-swap"}])
            iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role)
        st["profiles"] = [profile_a, profile_b]
        st["profile_roles"] = {profile_a: role_a, profile_b: role_b}

        ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
        reservation = _call_with_retry(
            lambda: ec2.run_instances(
                ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
                SubnetId=st["subnet"], SecurityGroupIds=[st["sg"]],
                IamInstanceProfile={"Name": profile_a},
                # IMDSv2 required: the probe fetches a token, so the stricter mode is asserted by
                # the probe working at all.
                MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
                TagSpecifications=[{"ResourceType": rt, "Tags": _tags(stem)}
                                   for rt in ("instance", "volume")],
            ),
            codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
        )
        st["instance"] = reservation["Instances"][0]["InstanceId"]
        instance_id = st["instance"]

        _poll(
            lambda: _instance_states(ec2, instance_id),
            lambda states: states == ["running"],
            timeout_s=_INSTANCE_RUNNING_TIMEOUT_S,
            what=f"instance {instance_id} reaching running",
        )

        def _agent():
            for page in ssm.get_paginator("describe_instance_information").paginate():
                for info in page["InstanceInformationList"]:
                    if info.get("InstanceId") == instance_id:
                        return info
            return None

        agent = _poll(_agent, lambda i: i is not None and i.get("PingStatus") == "Online",
                      timeout_s=_AGENT_ONLINE_TIMEOUT_S,
                      what=f"the SSM agent on {instance_id} coming Online")
        assert agent["ResourceType"] == "EC2Instance", (
            f"the side-channel must be a real EC2 instance; SSM reports "
            f"{agent['ResourceType']!r}"
        )

        # --- phase 1: what IMDS serves under role A, and what it can do -------------------
        marker_a = ctx.unique_name("m1-")
        first = _run_probe(ssm, instance_id, _probe_script(ctx.region, bucket, marker_a))

        assert first["listed_role"] == role_a, (
            f"IMDS must list the role currently in the instance profile; expected {role_a!r}, the "
            f"credentials path listed {first['listed_role']!r}"
        )
        assert first["code"] == "Success", (
            f"the credentials document must report Code 'Success', got {first['code']!r}"
        )
        assert first["cred_type"] == "AWS-HMAC", (
            f"the credentials document must report Type 'AWS-HMAC', got {first['cred_type']!r}"
        )
        assert first["akid_prefix"] == "ASIA", (
            f"instance-profile credentials are temporary, so the AccessKeyId must carry the STS "
            f"'ASIA' prefix; got {first['akid_prefix']!r}"
        )
        assert first["has_secret"] and first["has_token"], (
            f"the document must carry both SecretAccessKey and Token; got has_secret="
            f"{first['has_secret']!r} has_token={first['has_token']!r}"
        )
        assert first["expiration"], (
            f"the document must carry an Expiration, got {first['expiration']!r}"
        )
        assert first["info_profile_arn"].endswith(f"instance-profile/{profile_a}"), (
            f"iam/info must name the profile this check attached ({profile_a!r}); IMDS reported "
            f"{first['info_profile_arn']!r}"
        )
        assert first["a_rc"] == 0, (
            f"role A grants s3:PutObject on {_PREFIX_A}/* only, so that write must succeed with "
            f"the credentials IMDS served; the guest exited {first['a_rc']!r} with "
            f"{first['a_err']!r}"
        )
        assert first["b_rc"] != 0, (
            f"role A grants nothing on {_PREFIX_B}/*, so that write must be refused; the guest "
            f"exited {first['b_rc']!r} with {first['b_err']!r}"
        )
        code, message = _cli_error(first["b_err"])
        assert code == "AccessDenied", (
            f"role A grants nothing on {_PREFIX_B}/*, so that write must be refused with "
            f"AccessDenied; got {code!r} err={first['b_err']!r}"
        )
        expected = _no_identity_policy_message(
            account, role_a, instance_id, f"{bucket}/{_PREFIX_B}/{marker_a}")
        assert message == expected, (
            f"AccessDenied message for role A's write outside its prefix: expected {expected!r}, "
            f"got {message!r}"
        )
        head_a = s3.head_object(Bucket=bucket, Key=f"{_PREFIX_A}/{marker_a}")
        assert head_a["ContentLength"] == 0, (
            f"the authorized write must be present at S3; HeadObject reports {head_a!r}"
        )
        denied = _s3_head_code(s3, bucket, f"{_PREFIX_B}/{marker_a}")
        assert denied == "404", (
            f"the refused write must have created nothing; HeadObject on {_PREFIX_B}/{marker_a} "
            f"answered {denied!r}"
        )

        # --- phase 2: swap which INSTANCE PROFILE is associated with the running instance.
        # Changing the role inside an already-attached profile does not reach IMDS; replacing the
        # association with a different profile is the supported way without a restart.
        assocs = ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        )["IamInstanceProfileAssociations"]
        live = [a for a in assocs if a["State"] in ("associating", "associated")]
        assert len(live) == 1, (
            f"instance {instance_id} must have exactly one live instance-profile association "
            f"before the swap; DescribeIamInstanceProfileAssociations reports {assocs!r}"
        )
        replaced = ec2.replace_iam_instance_profile_association(
            IamInstanceProfile={"Name": profile_b}, AssociationId=live[0]["AssociationId"],
        )["IamInstanceProfileAssociation"]
        st["assoc_id"] = replaced["AssociationId"]
        assert replaced["IamInstanceProfile"]["Arn"].endswith(f"instance-profile/{profile_b}"), (
            f"the replaced association must name {profile_b!r}; "
            f"ReplaceIamInstanceProfileAssociation reports {replaced!r}"
        )

        # A fresh marker every attempt: a pre-swap attempt still writes role-a/<marker>, so the
        # assertions below use only the winning attempt's own marker.
        second = _poll(
            lambda: _run_probe(
                ssm, instance_id, _probe_script(ctx.region, bucket, ctx.unique_name("m2-"))),
            lambda p: p["listed_role"] == role_b and p["akid_sha"] not in ("", first["akid_sha"]),
            timeout_s=_IMDS_ROLE_SWAP_TIMEOUT_S,
            interval_s=15.0,
            what=f"IMDS on {instance_id} serving {role_b!r} with credentials different from the "
                 f"ones it served for {role_a!r}",
        )
        marker_b = second["marker"]
        assert marker_b, f"the winning probe attempt reported no marker: {second!r}"
        assert second["listed_role"] == role_b, (
            f"after the swap IMDS must list {role_b!r}; it listed {second['listed_role']!r}"
        )
        assert second["akid_sha"] != first["akid_sha"], (
            f"the endpoint must serve DIFFERENT credentials after the swap; the AccessKeyId hash "
            f"is unchanged at {second['akid_sha']!r}"
        )
        assert second["code"] == "Success", (
            f"the post-swap document must report Code 'Success', got {second['code']!r}"
        )
        assert second["info_profile_arn"].endswith(f"instance-profile/{profile_b}"), (
            f"iam/info must name the swapped-in profile ({profile_b!r}); IMDS reported "
            f"{second['info_profile_arn']!r}"
        )

        # --- the verdicts must invert -----------------------------------------------------
        assert second["b_rc"] == 0, (
            f"role B grants s3:PutObject on {_PREFIX_B}/* only, so that write must now succeed; "
            f"the guest exited {second['b_rc']!r} with {second['b_err']!r}"
        )
        assert second["a_rc"] != 0, (
            f"role B grants nothing on {_PREFIX_A}/*, so the write that succeeded under role A "
            f"must now be refused; the guest exited {second['a_rc']!r} with {second['a_err']!r}"
        )
        code, message = _cli_error(second["a_err"])
        assert code == "AccessDenied", (
            f"role B grants nothing on {_PREFIX_A}/*, so that write must be refused with "
            f"AccessDenied; got {code!r} err={second['a_err']!r}"
        )
        expected = _no_identity_policy_message(
            account, role_b, instance_id, f"{bucket}/{_PREFIX_A}/{marker_b}")
        assert message == expected, (
            f"AccessDenied message for role B's write outside its prefix: expected {expected!r}, "
            f"got {message!r}"
        )
        head_b = s3.head_object(Bucket=bucket, Key=f"{_PREFIX_B}/{marker_b}")
        assert head_b["ContentLength"] == 0, (
            f"the newly authorized write must be present at S3; HeadObject reports {head_b!r}"
        )
        now_denied = _s3_head_code(s3, bucket, f"{_PREFIX_A}/{marker_b}")
        assert now_denied == "404", (
            f"the newly refused write must have created nothing; HeadObject on "
            f"{_PREFIX_A}/{marker_b} answered {now_denied!r}"
        )
        # The role-A object written in phase 1 is untouched: the swap withdrew permission, it did
        # not rewrite history.
        still = s3.head_object(Bucket=bucket, Key=f"{_PREFIX_A}/{marker_a}")
        assert still["ETag"] == head_a["ETag"], (
            f"the object written under role A must survive the swap unchanged; ETag was "
            f"{head_a['ETag']!r} and is now {still['ETag']!r}"
        )
    finally:
        _teardown(ec2, iam, st)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
