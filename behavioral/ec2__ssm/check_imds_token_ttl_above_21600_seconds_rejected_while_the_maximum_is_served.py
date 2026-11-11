"""imds-token-ttl-above-21600-seconds-rejected-while-the-maximum-is-served."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "imds-token-ttl-above-21600-seconds-rejected-while-the-maximum-is-served"
GROUP = "guest-execution"
SERVICES = ["ec2", "ssm"]

_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_SUFFIX = ":iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_IID_PATH = "http://169.254.169.254/latest/meta-data/instance-id"
_TOKEN_PATH = "http://169.254.169.254/latest/api/token"
_MAX_TTL = 21600


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Poll probe() until predicate(result); AssertionError on timeout."""
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


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency"),
                       attempts=40, delay=5.0):
    """Delete, tolerating 'already gone' and retrying 'still referenced'."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = _code(exc)
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH 'available' and offers instance_type — neither call answers both."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _network(ctx, scenario):
    """A dedicated VPC with one public subnet and an egress-only security group, all tagged at
    create so an abort cannot leave an untagged (unreapable) resource."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.174.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _delete_with_retry(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            gone=("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
                  "InvalidVpcID.NotFound"))
        _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
                           gone=("InvalidInternetGatewayID.NotFound",))

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"),
        gone=("InvalidRoute.NotFound", "InvalidRouteTableID.NotFound")))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.174.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-imdsttl-"), VpcId=vpc_id,
        Description="sim2real imds token ttl egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    policy_arn = f"arn:{partition}{_SSM_CORE_POLICY_SUFFIX}"
    name = ctx.unique_name("sim2real-imdsttl-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real imds token ttl managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_profile():
        _delete_with_retry(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name), gone=("NoSuchEntity",),
            busy=("DeleteConflict",))
        _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _instance_state(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated' — the subnet, group and VPC deletions depend on it."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _wait_online(ctx, instance_id, timeout_s=900):
    """Wait for the SSM agent on this host to report Online. Never registering is a FAIL."""
    ssm = ctx.client("ssm")

    def _view():
        for page in ssm.get_paginator("describe_instance_information").paginate(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]):
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll(_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=timeout_s, interval_s=10.0,
                 what=f"the SSM agent on {instance_id} coming Online")


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=300):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=300,
        Comment="sim2real imds token ttl probe"),
        codes=_THROTTLE + ("InvalidInstanceId",))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"{what}: invocation {command_id} reaching a terminal status")


def _marker(stdout, marker):
    """The text after `marker` on the LAST line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _ttl_probe_script():
    """Runs INSIDE the guest (169.254.169.254 is link-local). For each TTL: PUT for a token,
    record the status and byte count, then try the returned body AS a token on a metadata read."""
    lines = ["set -uo pipefail", "B=$(mktemp)", "R=$(mktemp)"]
    for label, ttl in (("MAX", _MAX_TTL), ("OVER", _MAX_TTL + 1)):
        lines += [
            f"S=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5 -X PUT {_TOKEN_PATH}"
            f" -H 'X-aws-ec2-metadata-token-ttl-seconds: {ttl}')",
            f'echo "GUEST-{label}-PUT-STATUS $S"',
            f'echo "GUEST-{label}-PUT-BYTES $(wc -c < "$B" | tr -d \' \')"',
            f"S=$(curl -s -o \"$R\" -w '%{{http_code}}' -m 5"
            f" -H \"X-aws-ec2-metadata-token: $(tr -d '\\r\\n' < \"$B\")\" {_IID_PATH})",
            f'echo "GUEST-{label}-READ-STATUS $S"',
            f'echo "GUEST-{label}-READ-BODY $(head -c 64 "$R")"',
        ]
    lines.append('rm -f "$B" "$R"')
    return lines


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """In the guest, an IMDSv2 token PUT with a TTL of 21601 s is refused 400 and its body used
    as a token reads 401 without the instance id, while a PUT for exactly 21600 s returns 200 and
    its token reads the instance's own id."""
    scenario = "imds-token-ttl-bound"
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            MetadataOptions={"HttpEndpoint": "enabled", "HttpTokens": "required",
                             "HttpPutResponseHopLimit": 1},
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
        ),
        # InvalidParameterValue: a just-created instance profile not yet visible to EC2.
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=5.0)
    instance_id = resv["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert resv["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {resv['Instances'][0]['Placement']!r}, not {az!r}"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, what=f"instance {instance_id} reaching 'running'")
    _wait_online(ctx, instance_id)

    inv = _run_shell(ctx, instance_id, _ttl_probe_script(), what="probing IMDS token TTL bounds")
    assert inv["Status"] == "Success" and inv["ResponseCode"] == 0, (
        f"the guest probe ended {inv['Status']!r} rc={inv.get('ResponseCode')!r}: "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    out = inv["StandardOutputContent"]

    # --- positive control: exactly the maximum TTL is served, and its token works ----------------
    assert _marker(out, "GUEST-MAX-PUT-STATUS") == "200", (
        f"a token PUT with TTL {_MAX_TTL} (the documented maximum) must be served with 200; the "
        f"guest saw {_marker(out, 'GUEST-MAX-PUT-STATUS')!r}. Full output: {out!r}"
    )
    max_bytes = _marker(out, "GUEST-MAX-PUT-BYTES")
    assert max_bytes is not None and int(max_bytes) > 0, (
        f"the {_MAX_TTL}s PUT must return a non-empty token, it returned {max_bytes!r} bytes"
    )
    assert _marker(out, "GUEST-MAX-READ-STATUS") == "200", (
        f"the {_MAX_TTL}s token must authorise a metadata read; the guest saw "
        f"{_marker(out, 'GUEST-MAX-READ-STATUS')!r}"
    )
    assert _marker(out, "GUEST-MAX-READ-BODY") == instance_id, (
        f"the {_MAX_TTL}s token's read must return this instance's id {instance_id!r}, got "
        f"{_marker(out, 'GUEST-MAX-READ-BODY')!r}"
    )

    # --- the refusal: one second over the maximum ------------------------------------------------
    assert _marker(out, "GUEST-OVER-PUT-STATUS") == "400", (
        f"a token PUT with TTL {_MAX_TTL + 1} must be refused with 400; the guest saw "
        f"{_marker(out, 'GUEST-OVER-PUT-STATUS')!r}. Full output: {out!r}"
    )
    assert _marker(out, "GUEST-OVER-READ-STATUS") == "401", (
        f"whatever the refused PUT returned must NOT work as a token -- a metadata read carrying it "
        f"must be refused with 401; the guest saw {_marker(out, 'GUEST-OVER-READ-STATUS')!r}"
    )
    assert instance_id not in (_marker(out, "GUEST-OVER-READ-BODY") or ""), (
        f"the read carrying the refused PUT's body must not return the instance id; it returned "
        f"{_marker(out, 'GUEST-OVER-READ-BODY')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
