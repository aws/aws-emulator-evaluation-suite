"""guest-imdsv1-read-rejected-once-http-tokens-is-required."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guest-imdsv1-read-rejected-once-http-tokens-is-required"
GROUP = 'guest-execution'
SERVICES = ['ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_IID_PATH = "http://169.254.169.254/latest/meta-data/instance-id"
_TOKEN_PATH = "http://169.254.169.254/latest/api/token"


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
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Built rather than borrowed: a fresh account may have no default VPC, and every resource is
    tagged in the same call that creates it, because an untagged EC2 resource is invisible to a
    tag search forever.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.172.0.0/16",
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
        VpcId=vpc_id, CidrBlock="10.172.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-guest-"), VpcId=vpc_id,
        Description="sim2real guest-execution egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-guest-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real guest-execution managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

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


def _launch(ctx, *, profile_name, subnet_id, sg_id, user_data, scenario, metadata_options=None):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    kw = {}
    if metadata_options is not None:
        kw["MetadataOptions"] = metadata_options
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            UserData=user_data,
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
            **kw,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=5.0)
    return resv["Instances"][0]


def _wait_online(ctx, instance_id, timeout_s=600):
    """Wait for the SSM agent on this host to report Online. Never registering is a FAIL."""
    ssm = ctx.client("ssm")

    def _view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
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
        Comment="sim2real guest-execution imds probe"))
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


def _imds_probe_script(instance_id):
    """A guest script that probes IMDS both ways and reports what the link-local service answered.

    Runs INSIDE the instance because 169.254.169.254 is link-local: no caller outside the guest can
    reach it, which is precisely why this behaviour is invisible to a wire fixture.
    """
    return [
        "set -uo pipefail",
        "B=$(mktemp)",
        # v1: no token at all. curl without -f still exits 0 on an HTTP error, so the status code
        # is the observation rather than the exit status.
        f"S1=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5 {_IID_PATH})",
        'echo "GUEST-V1-STATUS $S1"',
        'echo "GUEST-V1-BYTES $(wc -c < "$B" | tr -d \' \')"',
        f'if grep -q "{instance_id}" "$B"; then echo "GUEST-V1-HAS-IID yes";'
        ' else echo "GUEST-V1-HAS-IID no"; fi',
        # v2: mint a token, then read the same path with it.
        f"T=$(curl -s -m 5 -X PUT {_TOKEN_PATH}"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 120')",
        'echo "GUEST-TOKEN-BYTES $(printf %s "$T" | wc -c | tr -d \' \')"',
        f"S2=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5 -H \"X-aws-ec2-metadata-token: $T\""
        f" {_IID_PATH})",
        'echo "GUEST-V2-STATUS $S2"',
        'echo "GUEST-V2-BODY $(cat "$B")"',
        'rm -f "$B"',
    ]


def _metadata_options(ec2, instance_id):
    """The instance's MetadataOptions, read off a paginated DescribeInstances.

    Paginated because the account may hold other instances that push a reservation off page
    one.
    """
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst["MetadataOptions"]
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Requiring HttpTokens makes the live guest's IMDSv1 read return 401 with no metadata, while an
    IMDSv2 token read still returns the instance id; the same v1 read returned 200 just before.
    """
    scenario = "guest-imdsv1-rejected"
    ec2 = ctx.client("ec2")
    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    inst = _launch(
        ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id, scenario=scenario,
        # A minimal user data: the graded behaviour is IMDS's, not the script's.
        user_data="#!/bin/bash\nmkdir -p /var/lib/sim2real-guest\n",
        metadata_options={"HttpEndpoint": "enabled", "HttpTokens": "optional",
                          "HttpPutResponseHopLimit": 1, "InstanceMetadataTags": "disabled"},
    )
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    _wait_online(ctx, instance_id)

    opts = _metadata_options(ec2, instance_id)
    assert (opts["HttpTokens"], opts["State"]) == ("optional", "applied"), (
        f"the instance must start out serving IMDSv1 with the options applied, got {opts!r}"
    )

    # --- positive control: with HttpTokens=optional the guest reads metadata unauthenticated ---
    before = _run_shell(ctx, instance_id, _imds_probe_script(instance_id),
                        what="probing IMDS while HttpTokens=optional")
    assert before["Status"] == "Success", (
        f"the pre-flip probe was {before['Status']!r}: {before.get('StatusDetails')!r} "
        f"stderr={before.get('StandardErrorContent')!r}"
    )
    assert before["ResponseCode"] == 0, (
        f"pre-flip ResponseCode was {before['ResponseCode']!r}, "
        f"stderr={before.get('StandardErrorContent')!r}"
    )
    out = before["StandardOutputContent"]
    assert _marker(out, "GUEST-V1-STATUS") == "200", (
        f"with HttpTokens=optional an unauthenticated IMDS read must be served; the guest saw "
        f"status {_marker(out, 'GUEST-V1-STATUS')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-V1-HAS-IID") == "yes", (
        f"the unauthenticated read must have returned this instance's own id {instance_id!r}; the "
        f"guest reported {_marker(out, 'GUEST-V1-HAS-IID')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-V2-BODY") == instance_id, (
        f"the token-carrying read must return {instance_id!r}, got "
        f"{_marker(out, 'GUEST-V2-BODY')!r}"
    )

    # --- break exactly one thing: require the token -----------------------------
    # The guest sees the new setting once State is 'applied', without a reboot.
    ec2.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="required")
    applied = _poll(
        lambda: _metadata_options(ec2, instance_id),
        lambda o: o.get("HttpTokens") == "required" and o.get("State") == "applied",
        timeout_s=300, interval_s=5.0,
        what=f"MetadataOptions on {instance_id} reporting HttpTokens=required applied")
    assert applied["HttpEndpoint"] == "enabled", (
        f"requiring the token must not disable the endpoint itself, got {applied!r}"
    )

    # --- the refusal, and the token path still working, on the same machine -----
    after = _run_shell(ctx, instance_id, _imds_probe_script(instance_id),
                       what="probing IMDS while HttpTokens=required")
    assert after["Status"] == "Success", (
        f"the post-flip probe was {after['Status']!r}: {after.get('StatusDetails')!r} "
        f"stderr={after.get('StandardErrorContent')!r}"
    )
    assert after["ResponseCode"] == 0, (
        f"post-flip ResponseCode was {after['ResponseCode']!r}, "
        f"stderr={after.get('StandardErrorContent')!r}"
    )
    out2 = after["StandardOutputContent"]

    assert _marker(out2, "GUEST-V1-STATUS") == "401", (
        f"with HttpTokens=required the unauthenticated read must be refused with 401; the guest "
        f"saw status {_marker(out2, 'GUEST-V1-STATUS')!r}. Full probe output: {out2!r}"
    )
    assert _marker(out2, "GUEST-V1-HAS-IID") == "no", (
        f"the refused read must not carry the instance id {instance_id!r} in its body; the guest "
        f"reported {_marker(out2, 'GUEST-V1-HAS-IID')!r}. Full probe output: {out2!r}"
    )
    assert _marker(out2, "GUEST-V2-STATUS") == "200", (
        f"a read carrying a freshly minted IMDSv2 token must still be served; the guest saw status "
        f"{_marker(out2, 'GUEST-V2-STATUS')!r}. Full probe output: {out2!r}"
    )
    assert _marker(out2, "GUEST-V2-BODY") == instance_id, (
        f"the token-carrying read must return this instance's own id {instance_id!r}, got "
        f"{_marker(out2, 'GUEST-V2-BODY')!r}"
    )
    token_bytes = _marker(out2, "GUEST-TOKEN-BYTES")
    assert token_bytes is not None and int(token_bytes) > 0, (
        f"the guest must have been issued a non-empty IMDSv2 token by PUT /latest/api/token, it "
        f"measured {token_bytes!r} bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
