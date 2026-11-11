"""run-instances-subnet-scoped-policy-refuses-other-subnet."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-instances-subnet-scoped-policy-refuses-other-subnet"
GROUP = "authorization"
SERVICES = ["ec2", "iam", "ssm", "sts"]

_VPC_CIDR = "10.85.0.0/16"
_SUBNET_A_CIDR = "10.85.1.0/24"
_SUBNET_B_CIDR = "10.85.2.0/24"
_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_POLICY_NAME = "sim2real-behav-subnetscope"
_IAM_TIMEOUT_S = 300.0
_ERR_DRY_RUN = "DryRunOperation"
_ERR_UNAUTHORIZED = "UnauthorizedOperation"
_ENCODED_MARKER = "Encoded authorization failure message: "
_TOKEN_NOT_YET = ("InvalidClientTokenId", "The security token included in the request is invalid.")
_MSG_DRY_RUN = "Request would have succeeded, but DryRun flag is set."
_GONE_CODES = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
               "InvalidInstanceID.NotFound", "NoSuchEntity")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role whose ec2:RunInstances resource list names only one subnet's ARN can launch into
    that subnet but is refused UnauthorizedOperation, naming the other subnet's ARN, into any
    other subnet, and the refused dry run launches nothing."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    st: dict = {}
    _build(ctx, ec2, iam, sts, st)
    _legs(ctx, ec2, st)


# ===== the legs ==============================================================


def _legs(ctx, ec2, st) -> None:
    restricted = st["restricted_ec2"]
    marker = st["marker"]

    def dry_run(subnet_id):
        return lambda: restricted.run_instances(
            DryRun=True, ImageId=st["ami"], InstanceType=_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[st["sg"]],
            TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(marker)}],
        )

    # Allow ec2:RunInstances scoped to subnet A's ARN only. Until the policy propagates, subnet
    # A is refused UnauthorizedOperation exactly as subnet B is; only that code is retried.
    allowed = _poll(
        ctx,
        lambda: _client_error(dry_run(st["subnet_a"])),
        lambda err: err.get("Code") != _ERR_UNAUTHORIZED,
        timeout_s=_IAM_TIMEOUT_S, interval_s=10.0,
        what=(f"the restricted role's RunInstances(DryRun=True) into subnet A answering "
              f"{_ERR_DRY_RUN} once its policy scoped to subnet A's ARN has propagated"),
    )
    assert (allowed.get("Code"), allowed.get("Message")) == (_ERR_DRY_RUN, _MSG_DRY_RUN), (
        f"subnet A: expected {(_ERR_DRY_RUN, _MSG_DRY_RUN)!r}, got {allowed!r}"
    )

    # The policy is live, so subnet B's refusal is the resource scoping itself.
    subnet_b_arn = f"arn:aws:ec2:{ctx.region}:{st['account']}:subnet/{st['subnet_b']}"
    denied = _client_error(dry_run(st["subnet_b"]))
    message = denied.get("Message") or ""
    encoded = message.split(_ENCODED_MARKER, 1)[1] if _ENCODED_MARKER in message else ""
    assert (denied.get("Code"), message) == (_ERR_UNAUTHORIZED, (
        f"You are not authorized to perform this operation. User: {st['session_arn']} is not "
        f"authorized to perform: ec2:RunInstances on resource: {subnet_b_arn} because no "
        f"identity-based policy allows the ec2:RunInstances action. {_ENCODED_MARKER}{encoded}"
    )), f"subnet B: unexpected refusal {denied!r}"

    # The encoded blob is minted per failure; decoded, it names the denied subnet.
    decoded = json.loads(
        st["sts"].decode_authorization_message(EncodedMessage=encoded)["DecodedMessage"])
    got = (decoded["allowed"], decoded["explicitDeny"], decoded["context"]["action"],
           decoded["context"]["resource"], decoded["context"]["principal"]["arn"])
    assert got == (False, False, "RunInstances", subnet_b_arn, st["session_arn"]), (
        f"decoded authorization failure for subnet B: got {got!r}"
    )

    # effect absent: neither dry run created anything, read independently
    assert _by_marker(ec2, marker) == set(), (
        f"a DryRun RunInstances must launch nothing regardless of its authorization verdict; "
        f"DescribeInstances filtered on tag:sim2real-marker={marker!r} must report nothing, got "
        f"{sorted(_by_marker(ec2, marker))!r}"
    )

    # --- positive control: the real (non-dry-run) launch into subnet A, still allowed, works ---
    launched = restricted.run_instances(
        ImageId=st["ami"], InstanceType=_TYPE, MinCount=1, MaxCount=1,
        SubnetId=st["subnet_a"], SecurityGroupIds=[st["sg"]],
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(marker)},
                            {"ResourceType": "volume", "Tags": _tags_for(marker)}],
    )
    instance_id = launched["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate(ctx, ec2, instance_id))
    assert launched["Instances"][0]["SubnetId"] == st["subnet_a"], (
        f"the authorized real launch must land in subnet A, got "
        f"{launched['Instances'][0]['SubnetId']!r}"
    )
    described = _poll(
        ctx,
        lambda: _describe(ec2, instance_id), lambda i: i is not None,
        timeout_s=180.0, interval_s=5.0,
        what=f"instance {instance_id} becoming visible to DescribeInstances",
    )
    assert described["SubnetId"] == st["subnet_a"], (
        f"DescribeInstances must report subnet A for {instance_id}, got {described['SubnetId']!r}"
    )
    assert _by_marker(ec2, marker) == {instance_id}, (
        f"after the authorized real launch, DescribeInstances filtered on "
        f"tag:sim2real-marker={marker!r} must report exactly {{{instance_id!r}}}, got "
        f"{sorted(_by_marker(ec2, marker))!r}"
    )


# ===== the fixture ===========================================================


def _policy(ctx, st):
    region, account = ctx.region, st["account"]
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": "ec2:RunInstances",
        "Resource": [
            f"arn:aws:ec2:{region}:{account}:subnet/{st['subnet_a']}",
            f"arn:aws:ec2:{region}::image/ami-*",
            f"arn:aws:ec2:{region}:{account}:network-interface/*",
            f"arn:aws:ec2:{region}:{account}:instance/*",
            f"arn:aws:ec2:{region}:{account}:volume/*",
            f"arn:aws:ec2:{region}:{account}:security-group/*",
        ],
    }, {
        "Effect": "Allow",
        "Action": "ec2:CreateTags",
        "Resource": [
            f"arn:aws:ec2:{region}:{account}:instance/*",
            f"arn:aws:ec2:{region}:{account}:volume/*",
        ],
        "Condition": {"StringEquals": {"ec2:CreateAction": "RunInstances"}},
    }]})


def _build(ctx, ec2, iam, sts, st) -> None:
    name = ctx.unique_name("sim2real-b1subnet-")
    st["name"] = name
    st["marker"] = ctx.unique_name("sim2real-b1subnet-run-")
    caller = sts.get_caller_identity()
    st["account"] = caller["Account"]
    st["sts"] = sts

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    zones = sorted(_zones_offering(ec2, _TYPE))
    assert zones, f"no available zone offers {_TYPE!r} in {ctx.region}"
    az_a = zones[0]
    az_b = zones[1] if len(zones) > 1 else zones[0]

    subnet_a = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_A_CIDR, AvailabilityZone=az_a,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_a)))
    st["subnet_a"] = subnet_a

    subnet_b = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_B_CIDR, AvailabilityZone=az_b,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_b)))
    st["subnet_b"] = subnet_b

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real RunInstances subnet-scoped IAM check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_after_enis_drain(ctx, ec2, vpc_id, sg_id))
    st["sg"] = sg_id

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    st["ami"] = ami

    role_name = name + "-role"
    role_arn = iam.create_role(
        RoleName=role_name, Path="/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{st['account']}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=_tags_for(role_name),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name)))

    iam.put_role_policy(
        RoleName=role_name, PolicyName=_POLICY_NAME,
        PolicyDocument=_policy(ctx, st),
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)))

    assumed = _assume(sts, caller["Arn"], role_arn, name)
    creds = assumed["Credentials"]
    st["session_arn"] = assumed["AssumedRoleUser"]["Arn"]
    signed = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    _wait_for_credentials_active(ctx, signed)
    st["restricted_ec2"] = ctx.client("ec2", creds=signed)


def _assume(sts, caller_arn, role_arn, session_name):
    """AssumeRole, retrying only the exact refusal a just-created role's trust answers while it
    propagates, against a deadline."""
    not_yet = ("AccessDenied",
               f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}")
    deadline = time.monotonic() + _IAM_TIMEOUT_S
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name[:64])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != not_yet or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _wait_for_credentials_active(ctx, creds, *, timeout_s=60.0, interval_s=3.0):
    """Block until the assumed session itself authenticates, retrying only the exact refusal
    of a token STS has not yet propagated."""
    sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sts.get_caller_identity()
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _TOKEN_NOT_YET or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


# ===== teardown ==============================================================


def _terminate(ctx, ec2, instance_id) -> None:
    _unless_gone(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _poll(
        ctx, lambda: _state(ec2, instance_id), lambda s: s in ("terminated", "__gone__"),
        timeout_s=900.0, interval_s=10.0, what=f"instance {instance_id} reaching 'terminated'",
    )


def _delete_sg_after_enis_drain(ctx, ec2, vpc_id, sg_id) -> None:
    _poll(
        ctx, lambda: _vpc_enis(ec2, vpc_id), lambda enis: enis == [],
        timeout_s=420.0, interval_s=10.0, what=f"every ENI in {vpc_id!r} draining",
    )
    _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg_id))


# ===== helpers ===============================================================


def _tags_for(marker):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-marker", "Value": marker}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must fail as an acceptance, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, predicate, *, timeout_s, interval_s, what):
    """Bounded retry that RAISES on timeout -- never returns its last observation."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _unless_gone(fn):
    try:
        fn()
    except ClientError as exc:
        if _code(exc) not in _GONE_CODES:
            raise


def _retry_dependency(fn, attempts=24, delay=10.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "InvalidParameterDependency",
                                  "DeleteConflict", "RequestLimitExceeded") \
                    or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _by_marker(ec2, marker):
    found = set()
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real-marker", "Values": [marker]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["State"]["Name"] != "terminated":
                    found.add(inst["InstanceId"])
    return found


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


def _zones_offering(ec2, instance_type):
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    }
    assert usable, f"no available zone in this region offers {instance_type!r}"
    return usable


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
