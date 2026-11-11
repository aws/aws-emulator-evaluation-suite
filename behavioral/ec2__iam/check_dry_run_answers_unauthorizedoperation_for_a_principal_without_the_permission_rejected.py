"""dry-run-answers-unauthorizedoperation-for-a-principal-without-the-permission-rejected."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dry-run-answers-unauthorizedoperation-for-a-principal-without-the-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2", "iam"]

_VPC_CIDR = "10.81.0.0/16"
_SUBNET_CIDR = "10.81.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_POLICY_NAME = "sim2real-behav-dryrun"
_IAM_TIMEOUT_S = 300.0
_ERR_DRY_RUN = "DryRunOperation"
_ERR_UNAUTHORIZED = "UnauthorizedOperation"
_MSG_DRY_RUN = "Request would have succeeded, but DryRun flag is set."
_GONE_CODES = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
               "InvalidInstanceID.NotFound", "NoSuchEntity")
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopInstances(DryRun=True) answers DryRunOperation for a principal holding ec2:StopInstances
    and UnauthorizedOperation for one without it, the real call agrees, and granting the action
    flips both: DryRun is an authorization check, not a syntax check.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    st: dict = {"instances": [], "sgs": [], "subnets": [], "roles": []}
    try:
        _build(ctx, ec2, iam, sts, st)
        _legs(ctx, ec2, iam, st)
    finally:
        _teardown(ec2, iam, st)


# ===== the legs ==============================================================


def _legs(ctx, ec2, iam, st) -> None:
    instance_id = st["instance"]
    restricted = st["restricted_ec2"]

    # --- beat 1: the positive control, at the consumer. The session is healthy, not denied-all. ---
    seen = restricted.describe_instances(InstanceIds=[instance_id])["Reservations"]
    assert seen and seen[0]["Instances"][0]["InstanceId"] == instance_id, (
        f"the restricted session must be able to DESCRIBE the instance, otherwise every refusal "
        f"below is indistinguishable from a session that can do nothing at all; it saw {seen!r}"
    )
    assert seen[0]["Instances"][0]["State"]["Name"] == "running", (
        f"the instance must be running before the dry runs, got "
        f"{seen[0]['Instances'][0]['State']!r}"
    )
    caller = st["restricted_sts"].get_caller_identity()["Arn"]
    assert caller.startswith(f"arn:aws:sts::{st['account']}:assumed-role/{st['role']}/"), (
        f"the restricted client must sign AS the assumed role {st['role']!r}, not as the harness's "
        f"own identity; GetCallerIdentity returned {caller!r}"
    )

    # --- beat 2: the OWNER holds the permission, so its dry run says DryRunOperation ---
    owner = _client_error(
        lambda: ec2.stop_instances(InstanceIds=[instance_id], DryRun=True))
    assert owner.get("Code") == _ERR_DRY_RUN, (
        f"a principal that HOLDS ec2:StopInstances must get {_ERR_DRY_RUN} from a dry run; the "
        f"harness principal got {owner.get('Code')!r} ({owner.get('Message')!r})"
    )
    assert owner.get("Message") == _MSG_DRY_RUN, (
        f"the owner's {_ERR_DRY_RUN} message: expected {_MSG_DRY_RUN!r}, got {owner.get('Message')!r}"
    )
    assert _state(ec2, instance_id) == "running", (
        f"a dry run must not move the instance; after the owner's dry run it is "
        f"{_state(ec2, instance_id)!r}"
    )

    # --- beat 3: break exactly one thing — the PRINCIPAL. Same bytes, different identity. ---
    denied = _client_error(
        lambda: restricted.stop_instances(InstanceIds=[instance_id], DryRun=True))
    assert denied.get("Code") == _ERR_UNAUTHORIZED, (
        f"the SAME StopInstances(DryRun=True) request from a principal WITHOUT ec2:StopInstances "
        f"must answer {_ERR_UNAUTHORIZED}, not {_ERR_DRY_RUN}: a target that answers "
        f"{_ERR_DRY_RUN} here reports every caller as authorized for everything. Got "
        f"{denied.get('Code')!r} ({denied.get('Message')!r})"
    )
    # message varies: UnauthorizedOperation ends in an "Encoded authorization failure message"
    # blob that differs on every call, so only the code is graded.

    # --- beat 4: effect absent, read independently and at the consumer too ---
    assert _state(ec2, instance_id) == "running", (
        f"a refused dry run must not move the instance; it is {_state(ec2, instance_id)!r}"
    )
    consumer_view = restricted.describe_instances(
        InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert consumer_view["State"]["Name"] == "running", (
        f"the restricted principal's own read must also still see a running instance, got "
        f"{consumer_view['State']!r}"
    )

    # --- beat 4b: the dry run TOLD THE TRUTH — the real call is refused as well ---
    real = _client_error(lambda: restricted.stop_instances(InstanceIds=[instance_id]))
    assert real.get("Code") == _ERR_UNAUTHORIZED, (
        f"the restricted principal's REAL StopInstances must be refused with {_ERR_UNAUTHORIZED} "
        f"too, or the dry run's verdict was a lie; got {real.get('Code')!r} "
        f"({real.get('Message')!r})"
    )
    # message varies: the same per-call encoded authorization failure blob as the dry run above.
    assert _state(ec2, instance_id) == "running", (
        f"the refused real call must not have moved the instance; it is "
        f"{_state(ec2, instance_id)!r}"
    )

    # --- beat 5: restore. Grant the ONE missing action; the SAME dry run flips its verdict. ---
    iam.put_role_policy(
        RoleName=st["role"], PolicyName=_POLICY_NAME,
        PolicyDocument=_policy(allow_stop=True, instance_arn=st["instance_arn"]),
    )
    granted = _poll(
        lambda: _client_error(
            lambda: restricted.stop_instances(InstanceIds=[instance_id], DryRun=True)),
        lambda err: err.get("Code") == _ERR_DRY_RUN,
        timeout_s=_IAM_TIMEOUT_S, interval_s=10.0,
        what=(f"the restricted principal's identical StopInstances(DryRun=True) answering "
              f"{_ERR_DRY_RUN} once ec2:StopInstances is granted (it answered "
              f"{denied.get('Code')!r} before). IAM exposes no read that reports a policy as "
              f"effective, so this is a bounded retry on the verdict itself"),
    )
    assert granted.get("Code") == _ERR_DRY_RUN, (
        f"after the grant the identical dry run must answer {_ERR_DRY_RUN}, got {granted!r}"
    )
    assert granted.get("Message") == _MSG_DRY_RUN, (
        f"the granted dry run's {_ERR_DRY_RUN} message: expected {_MSG_DRY_RUN!r}, got "
        f"{granted.get('Message')!r}"
    )
    assert _state(ec2, instance_id) == "running", (
        f"even the AUTHORIZED dry run must not move the instance; it is "
        f"{_state(ec2, instance_id)!r}"
    )

    # --- beat 6: the terminal read. The now-authorized principal's REAL call does the work. ---
    stopping = restricted.stop_instances(InstanceIds=[instance_id])["StoppingInstances"]
    assert stopping and stopping[0]["InstanceId"] == instance_id, (
        f"the authorized real call must accept the stop for {instance_id!r}; got {stopping!r}"
    )
    assert stopping[0]["CurrentState"]["Name"] == "stopping", (
        f"the authorized real call must start the stop, reporting the transient 'stopping' state; "
        f"got {stopping[0]!r}"
    )
    _poll(lambda: _state(ec2, instance_id), lambda s: s == "stopped",
          timeout_s=900.0, interval_s=10.0,
          what=(f"{STATE_MARKER}: instance {instance_id} reaching 'stopped' after the newly "
                f"authorized principal stopped it"))
    final = _describe(ec2, instance_id)
    assert final is not None and final["State"]["Name"] == "stopped", (
        f"the independent read must show the instance stopped, got {final and final['State']!r}"
    )


# ===== the fixture ===========================================================


def _policy(*, allow_stop, instance_arn):
    """The restricted role's inline policy. Describe is ALWAYS allowed, so the positive control
    exists; Stop is the one action that moves between the two arms."""
    statements = [
        {"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"},
    ]
    if allow_stop:
        statements.append(
            {"Effect": "Allow", "Action": ["ec2:StopInstances"], "Resource": instance_arn})
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _build(ctx, ec2, iam, sts, st) -> None:
    name = ctx.unique_name("sim2real-b1dry-")
    st["name"] = name
    st["account"] = sts.get_caller_identity()["Account"]

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az = sorted(_zones_offering(ec2, _INSTANCE_TYPE))[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real EC2 DryRun authorization check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": _tags_for(name)},
            {"ResourceType": "volume", "Tags": _tags_for(name)},
        ],
    )["Instances"][0]["InstanceId"]
    st["instances"].append(instance_id)
    st["instance"] = instance_id
    st["instance_arn"] = f"arn:aws:ec2:{ctx.region}:{st['account']}:instance/{instance_id}"
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    _poll(lambda: _state(ec2, instance_id), lambda s: s == "running",
          timeout_s=900.0, interval_s=10.0,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'running'")

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
    st["roles"].append(role_name)
    st["role"] = role_name
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_POLICY_NAME,
        PolicyDocument=_policy(allow_stop=False, instance_arn=st["instance_arn"]),
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)))
    attached = iam.get_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)["PolicyDocument"]
    assert "ec2:StopInstances" not in json.dumps(attached), (
        f"the restricted role must NOT hold ec2:StopInstances at the start, or beat 3 asserts "
        f"nothing; its inline policy is {attached!r}"
    )

    creds = _assume(sts, role_arn, name)
    signed = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    # ctx.client's `creds` override signs as the minted principal while keeping THIS target's
    # endpoint and TLS wiring — the sanctioned re-signing idiom. A hand-rolled boto3.client here
    # would send the asserted request to real AWS on an emulator run.
    st["restricted_ec2"] = ctx.client("ec2", creds=signed)
    st["restricted_sts"] = ctx.client("sts", creds=signed)


def _assume(sts, role_arn, session_name):
    """AssumeRole against a just-created role transiently 403s until the trust policy propagates.
    IAM exposes no API reporting a trust policy as effective, so the wait IS the bounded retry."""
    deadline = time.monotonic() + _IAM_TIMEOUT_S
    last = None
    while True:
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name[:64])["Credentials"]
        except ClientError as exc:
            last = _code(exc)
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not assume {role_arn} within {_IAM_TIMEOUT_S}s; last error {last!r}"
                ) from exc
            time.sleep(5.0)


# ===== in-band teardown ======================================================


def _teardown(ec2, iam, st) -> None:
    left: list[str] = []

    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone():
        still = ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]
        if still:
            raise AssertionError(f"vpc {st['vpc']} is still describable: {still!r}")

    for role in st.get("roles", []):
        _step(f"role-policy {role}", lambda r=role: iam.delete_role_policy(
            RoleName=r, PolicyName=_POLICY_NAME))
        _step(f"role {role}", lambda r=role: iam.delete_role(RoleName=r))
    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _poll(
            lambda: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
            timeout_s=900.0, interval_s=10.0, what=f"instance {i} reaching 'terminated'"))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420.0, interval_s=10.0, what=f"every ENI in {st['vpc']!r} draining"))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", _vpc_gone)
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 - collected, raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


# ===== helpers ===============================================================


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _unless_gone(fn):
    """Cleanup backstop for a resource `_teardown` may already have removed: a gone code is the
    goal state; any other error propagates."""
    try:
        fn()
    except ClientError as exc:
        if _code(exc) not in _GONE_CODES:
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses must fail as an acceptance, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded retry that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


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
