"""spotint-cancelling-a-fulfilled-spot-request-leaves-the-guest-running-with-no-notice."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "spotint-cancelling-a-fulfilled-spot-request-leaves-the-guest-running-with-no-notice"
GROUP = 'spot-interruption'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: The smallest size that exhibits the behaviour. Spot is a property of the PURCHASE, not of the
#: family, so t3.micro is both sufficient and the cheapest thing that can be interrupted at all.
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_IMDS = "http://169.254.169.254/latest"
_VPC_CIDR = "10.183.0.0/16"
_SUBNET_CIDR = "10.183.1.0/24"
_HTTP_OK = "200"
_HTTP_NOT_FOUND = "404"

# ===== helpers =====


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
    """An AZ that is BOTH 'available' and offers instance_type — neither call answers both.

    An empty intersection means this region cannot run the check at all, which is a finding rather
    than an AZ to guess at, so it is asserted instead of defaulted.
    """
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

    Built rather than borrowed: a fresh account may have no default VPC. Every resource is tagged
    in the same call that creates it.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
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
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-spotint-"), VpcId=vpc_id,
        Description="sim2real spot-interruption guest probe egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-spotint-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real spot-interruption managed instance role",
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


def _instance(ec2, instance_id):
    """The instance record, read off a PAGINATED DescribeInstances.

    Paginated because other instances in the account can push the reservation off page one.
    """
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


def _spot_request(ec2, request_id):
    """The spot request record off a PAGINATED describe, or None if it is not visible yet.

    A request whose id RunInstances has already handed back is not immediately describable by that id
    (measured: InvalidSpotInstanceRequestID.NotFound for the first few seconds), so 'not there yet'
    is None and every caller polls rather than reading it as a verdict.
    """
    try:
        for page in ec2.get_paginator("describe_spot_instance_requests").paginate(
                SpotInstanceRequestIds=[request_id]):
            for req in page["SpotInstanceRequests"]:
                if req["SpotInstanceRequestId"] == request_id:
                    return req
    except ClientError as exc:
        if _code(exc) != "InvalidSpotInstanceRequestID.NotFound":
            raise
    return None


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


def _cancel_quietly(ec2, request_id):
    """Cancel the implicit spot request, tolerating an already-cancelled one.

    RunInstances mints the request, so this is the second half of a teardown whose first half is the
    instance terminate: an uncancelled one-time request whose instance is gone is harmless, but
    leaving it 'active' in DescribeSpotInstanceRequests pollutes every later run's listing.
    """
    try:
        _call_with_retry(
            lambda: ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[request_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidSpotInstanceRequestID.NotFound":
            raise


def _wait_online(ctx, instance_id, timeout_s=900):
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
        Comment="sim2real spot-interruption imds probe"))
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


def _spot_notice_probe_script():
    """A guest script that asks IMDS the two interruption-notice questions and one control question.

    Runs INSIDE the instance because 169.254.169.254 is link-local: no caller outside the guest can
    reach it. Every answer is reported as the HTTP STATUS plus a STRUCTURAL verdict on the body —
    does it parse as an interruption notice at all — so "no notice" is asserted as the absence of
    the notice's own shape rather than as a byte count.
    """
    return [
        "set -uo pipefail",
        # IMDSv2 only: the AL2023 AMI declares ImdsSupport=v2.0, so every read carries a token.
        f"T=$(curl -s -m 5 -X PUT {_IMDS}/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 120')",
        'echo "GUEST-TOKEN-BYTES $(printf %s "$T" | wc -c | tr -d \' \')"',
        "B=$(mktemp)",
        # --- control: IMDS answers at all, and answers about THIS instance ---
        f"S=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5"
        f" -H \"X-aws-ec2-metadata-token: $T\" {_IMDS}/meta-data/instance-id)",
        'echo "GUEST-IID-STATUS $S"',
        'echo "GUEST-IID-BODY $(cat "$B")"',
        # --- the guest's own view of its purchase: this is what makes the check spot-specific ---
        f"S=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5"
        f" -H \"X-aws-ec2-metadata-token: $T\" {_IMDS}/meta-data/instance-life-cycle)",
        'echo "GUEST-LIFECYCLE-STATUS $S"',
        'echo "GUEST-LIFECYCLE-BODY $(cat "$B")"',
        # --- notice path 1: spot/instance-action ---
        f"S=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5"
        f" -H \"X-aws-ec2-metadata-token: $T\" {_IMDS}/meta-data/spot/instance-action)",
        'echo "GUEST-ACTION-STATUS $S"',
        'echo "GUEST-ACTION-BYTES $(wc -c < "$B" | tr -d \' \')"',
        # A real notice is {"action": "...", "time": "...Z"}: the JSON key is its signature.
        'if grep -q \'"action"\' "$B"; then echo "GUEST-ACTION-HAS-KEY yes";'
        ' else echo "GUEST-ACTION-HAS-KEY no"; fi',
        'if grep -Eq \'(terminate|hibernate|stop)\' "$B"; then echo "GUEST-ACTION-HAS-VERB yes";'
        ' else echo "GUEST-ACTION-HAS-VERB no"; fi',
        # --- notice path 2: spot/termination-time ---
        f"S=$(curl -s -o \"$B\" -w '%{{http_code}}' -m 5"
        f" -H \"X-aws-ec2-metadata-token: $T\" {_IMDS}/meta-data/spot/termination-time)",
        'echo "GUEST-TERMTIME-STATUS $S"',
        'echo "GUEST-TERMTIME-BYTES $(wc -c < "$B" | tr -d \' \')"',
        # A real termination-time body is a bare ISO-8601 instant and nothing else.
        'if grep -Eq \'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\' "$B";'
        ' then echo "GUEST-TERMTIME-HAS-ISO yes"; else echo "GUEST-TERMTIME-HAS-ISO no"; fi',
        'rm -f "$B"',
    ]


def _assert_no_notice(out, *, instance_id, when):
    """Assert the guest saw a live spot instance with NEITHER interruption notice present."""
    token_bytes = _marker(out, "GUEST-TOKEN-BYTES")
    assert token_bytes is not None and int(token_bytes) > 0, (
        f"[{when}] the guest must have been issued a non-empty IMDSv2 session token by "
        f"PUT /latest/api/token; it measured {token_bytes!r} bytes. Full probe output: {out!r}"
    )
    # The control comes first: without it a 404 below proves only that IMDS is broken.
    assert _marker(out, "GUEST-IID-STATUS") == _HTTP_OK, (
        f"[{when}] IMDS must answer the instance-identity read with {_HTTP_OK}; the guest saw "
        f"{_marker(out, 'GUEST-IID-STATUS')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-IID-BODY") == instance_id, (
        f"[{when}] the guest's own IMDS must report this instance's id {instance_id!r}, got "
        f"{_marker(out, 'GUEST-IID-BODY')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-LIFECYCLE-STATUS") == _HTTP_OK, (
        f"[{when}] /meta-data/instance-life-cycle must answer {_HTTP_OK} on a spot instance; the "
        f"guest saw {_marker(out, 'GUEST-LIFECYCLE-STATUS')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-LIFECYCLE-BODY") == "spot", (
        f"[{when}] the GUEST must see itself as a spot instance: /meta-data/instance-life-cycle "
        f"must read 'spot', got {_marker(out, 'GUEST-LIFECYCLE-BODY')!r}. A DescribeInstances "
        f"field echoing what RunInstances accepted proves nothing about what booted. "
        f"Full probe output: {out!r}"
    )
    # The notice paths: present as paths, empty of content, while the instance is healthy.
    assert _marker(out, "GUEST-ACTION-STATUS") == _HTTP_NOT_FOUND, (
        f"[{when}] /meta-data/spot/instance-action must answer {_HTTP_NOT_FOUND} while the "
        f"instance is not marked for interruption; the guest saw "
        f"{_marker(out, 'GUEST-ACTION-STATUS')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-ACTION-HAS-KEY") == "no", (
        f"[{when}] the refused instance-action read must carry no notice: its body contained the "
        f"\"action\" key ({_marker(out, 'GUEST-ACTION-BYTES')!r} bytes). A target that serves an "
        f"interruption notice to a healthy instance is the over-permissive failure this check "
        f"exists to catch. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-ACTION-HAS-VERB") == "no", (
        f"[{when}] the refused instance-action read must not name an interruption verb "
        f"(terminate/hibernate/stop); the guest reported "
        f"{_marker(out, 'GUEST-ACTION-HAS-VERB')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-TERMTIME-STATUS") == _HTTP_NOT_FOUND, (
        f"[{when}] /meta-data/spot/termination-time must answer {_HTTP_NOT_FOUND} while the "
        f"instance is not marked for interruption; the guest saw "
        f"{_marker(out, 'GUEST-TERMTIME-STATUS')!r}. Full probe output: {out!r}"
    )
    assert _marker(out, "GUEST-TERMTIME-HAS-ISO") == "no", (
        f"[{when}] the refused termination-time read must carry no timestamp; the guest matched "
        f"an ISO-8601 instant in its body ({_marker(out, 'GUEST-TERMTIME-BYTES')!r} bytes). "
        f"Full probe output: {out!r}"
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Cancelling the spot request behind a running spot instance is not an interruption: the request
    goes cancelled/request-canceled-and-instance-running, the instance stays running and its guest's
    IMDS still reports 'spot' with both interruption-notice paths answering 404."""
    scenario = "spotint-cancel-leaves-guest"
    ec2 = ctx.client("ec2")
    subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"

    tag = [{"Key": "sim2real", "Value": scenario},
           {"Key": "Name", "Value": ctx.unique_name("sim2real-spotint-")}]
    inst = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            InstanceMarketOptions={"MarketType": "spot", "SpotOptions": {
                "SpotInstanceType": "one-time", "InstanceInterruptionBehavior": "terminate"}},
            # Tagged in the creating call, never in a follow-up an abort could skip.
            TagSpecifications=[{"ResourceType": rt, "Tags": tag}
                               for rt in ("instance", "volume")],
        ),
        # A role created seconds ago is not yet assumable by ec2.amazonaws.com; EC2 reports that as
        # InvalidParameterValue on the instance profile.
        codes=_THROTTLE + ("InvalidParameterValue",), retries=100, delay=2.0,
    )["Instances"][0]
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))

    assert inst["InstanceLifecycle"] == "spot", (
        f"RunInstances with MarketType 'spot' must mint a spot instance: expected "
        f"InstanceLifecycle='spot', got {inst.get('InstanceLifecycle')!r}"
    )
    request_id = inst.get("SpotInstanceRequestId")
    assert request_id, (
        f"a spot instance launched through InstanceMarketOptions must carry the implicit request's "
        f"id; RunInstances reported {request_id!r}"
    )
    ctx.on_cleanup(lambda: _cancel_quietly(ec2, request_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    fulfilled = _poll(
        lambda: _spot_request(ec2, request_id),
        lambda r: r is not None and r["State"] == "active",
        timeout_s=300, interval_s=5.0,
        what=f"the implicit spot request {request_id} reaching state 'active'")
    assert fulfilled["Status"]["Code"] == "fulfilled", (
        f"the implicit request behind a running spot instance must report status code 'fulfilled', "
        f"got {fulfilled['Status']!r}"
    )
    assert fulfilled["InstanceId"] == instance_id, (
        f"the request must point at the instance RunInstances returned ({instance_id!r}), got "
        f"{fulfilled.get('InstanceId')!r}"
    )
    _wait_online(ctx, instance_id)

    # --- before: the guest is a healthy spot instance with no notice -----------------------------
    before = _run_shell(ctx, instance_id, _spot_notice_probe_script(),
                        what="probing the interruption-notice paths before the cancel")
    assert before["Status"] == "Success", (
        f"the pre-cancel in-guest probe was {before['Status']!r}: "
        f"{before.get('StatusDetails')!r} stderr={before.get('StandardErrorContent')!r}"
    )
    assert before["ResponseCode"] == 0, (
        f"the pre-cancel in-guest probe exited {before['ResponseCode']!r}, "
        f"stderr={before.get('StandardErrorContent')!r}"
    )
    _assert_no_notice(before["StandardOutputContent"], instance_id=instance_id,
                      when="before the cancel")

    # --- break exactly one thing: cancel the request the running instance came from ---------------
    cancelled = _call_with_retry(lambda: ec2.cancel_spot_instance_requests(
        SpotInstanceRequestIds=[request_id]))["CancelledSpotInstanceRequests"]
    assert [c["SpotInstanceRequestId"] for c in cancelled] == [request_id], (
        f"CancelSpotInstanceRequests must acknowledge exactly {request_id!r}, got {cancelled!r}"
    )
    after_request = _poll(
        lambda: _spot_request(ec2, request_id),
        lambda r: r is not None and r["State"] == "cancelled",
        timeout_s=180, interval_s=5.0,
        what=f"spot request {request_id} reaching state 'cancelled'")
    assert after_request["Status"]["Code"] == "request-canceled-and-instance-running", (
        f"a cancelled request whose instance survives must say so: expected status code "
        f"'request-canceled-and-instance-running', got {after_request['Status']!r}"
    )

    # --- the effect that must be ABSENT: the instance was not reclaimed ---------------------------
    assert _instance_state(ec2, instance_id) == "running", (
        f"cancelling the request must not terminate the instance it launched; {instance_id} is "
        f"{_instance_state(ec2, instance_id)!r}"
    )
    still = _instance(ec2, instance_id)
    assert still["InstanceLifecycle"] == "spot", (
        f"the surviving instance is still a spot instance: expected InstanceLifecycle='spot', got "
        f"{still.get('InstanceLifecycle')!r}"
    )
    assert "StateReason" not in still, (
        f"an instance that was not interrupted must carry no StateReason; it reported "
        f"{still.get('StateReason')!r}"
    )

    # --- and the guest agrees, which is the only place this is really observable ------------------
    after = _run_shell(ctx, instance_id, _spot_notice_probe_script(),
                       what="probing the interruption-notice paths after the cancel")
    assert after["Status"] == "Success", (
        f"the post-cancel in-guest probe was {after['Status']!r}: "
        f"{after.get('StatusDetails')!r} stderr={after.get('StandardErrorContent')!r}"
    )
    assert after["ResponseCode"] == 0, (
        f"the post-cancel in-guest probe exited {after['ResponseCode']!r}, "
        f"stderr={after.get('StandardErrorContent')!r}"
    )
    _assert_no_notice(after["StandardOutputContent"], instance_id=instance_id,
                      when="after the cancel")

    # --- closing the state machine: the terminate is what the request records ---------------------
    _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    final = _poll(
        lambda: _spot_request(ec2, request_id),
        lambda r: r is not None and r["Status"]["Code"] != "request-canceled-and-instance-running",
        timeout_s=600, interval_s=10.0,
        what=f"spot request {request_id} recording the user-initiated termination")
    assert final["Status"]["Code"] == "instance-terminated-by-user", (
        f"terminating the instance by hand must be recorded on the request as "
        f"'instance-terminated-by-user', got {final['Status']!r}"
    )
    assert final["State"] == "cancelled", (
        f"the request stays in the state the cancel put it in; expected 'cancelled', got "
        f"{final['State']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
