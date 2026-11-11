"""run-command-nonzero-exit-surfaces-as-failed-with-the-exact-response-code."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-command-nonzero-exit-surfaces-as-failed-with-the-exact-response-code"
GROUP = "run-command"
SERVICES = ["ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_EXIT_CODE = 42
_STDERR_MARKER = "sim2real-behav-stderr-marker"
_STDOUT_MARKER = "sim2real-behav-stdout-marker"
_TAG = [{"Key": "sim2real", "Value": "run-command-nonzero-exit"}]


def _error_code(fn):
    """Return the ClientError (code, message) raised by fn, or raise if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "the call was expected to be refused but it succeeded; returning a falsy "
        "sentinel here would let an over-permissive target launder acceptance"
    )


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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s "
                f"(last observed: {last!r})"
            )
        time.sleep(interval_s)


def _usable_az(ec2):
    """An AZ that both is available and offers the instance type."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offered "
        f"{sorted(offered)!r}, available {sorted(available)!r}"
    )
    return usable[0]


def _delete_with_retry(fn, gone, busy=("DependencyViolation",), attempts=40, delay=5.0):
    """Delete, tolerating 'already gone' and retrying 'still referenced'."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _network(ctx, ec2, st):
    """A dedicated VPC with one public subnet, an internet gateway and a default route.

    The SSM agent must reach the SSM endpoint to register; the default security group allows egress.
    """
    zone = _usable_az(ec2)
    tag = [{"ResourceType": rt, "Tags": _TAG}
           for rt in ("vpc", "internet-gateway", "subnet")]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.174.0.0/16", TagSpecifications=[tag[0]]
    )["Vpc"]["VpcId"]
    net = {"vpc": vpc_id, "igw": None, "subnet": None}
    st["networks"].append(net)
    ctx.on_cleanup(lambda: _drop_network(ec2, net, attempts=6))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[tag[1]]
    )["InternetGateway"]["InternetGatewayId"]
    net["igw"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rtb_id = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "association.main", "Values": ["true"]},
        ]
    )["RouteTables"][0]["RouteTableId"]
    ec2.create_route(
        RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.174.1.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[tag[2]],
    )["Subnet"]["SubnetId"]
    net["subnet"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    return subnet_id, zone


def _drop_network(ec2, net, attempts=40):
    """Delete the subnet, internet gateway and VPC; route table and security group go with it."""
    if net.get("subnet"):
        _delete_with_retry(
            lambda: ec2.delete_subnet(SubnetId=net["subnet"]),
            gone=("InvalidSubnetID.NotFound",),
            attempts=attempts,
        )
    if net.get("igw"):
        _delete_with_retry(
            lambda: ec2.detach_internet_gateway(
                InternetGatewayId=net["igw"], VpcId=net["vpc"]
            ),
            gone=(
                "Gateway.NotAttached",
                "InvalidInternetGatewayID.NotFound",
                "InvalidVpcID.NotFound",
            ),
            attempts=attempts,
        )
        _delete_with_retry(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]),
            gone=("InvalidInternetGatewayID.NotFound",),
            attempts=attempts,
        )
    _delete_with_retry(
        lambda: ec2.delete_vpc(VpcId=net["vpc"]),
        gone=("InvalidVpcID.NotFound",),
        attempts=attempts,
    )


def _terminate_and_wait(ec2, instance_id, timeout_s=300):
    """Terminate and wait for `terminated`; only then is its ENI gone and the subnet deletable."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = _instance_states(ec2, instance_id)
        if states is None or all(s == "terminated" for s in states):
            return
        time.sleep(5)


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _instance_states(ec2, instance_id):
    """The states EC2 reports, or None if the instance record is gone entirely."""
    try:
        return [
            i["State"]["Name"]
            for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            for i in r["Instances"]
        ]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return None
        raise


def _teardown(ec2, iam, st):
    """Remove everything this check created; return what could not be removed."""
    left = []
    for instance_id in st["instances"]:
        _terminate_and_wait(ec2, instance_id)
        states = _instance_states(ec2, instance_id)
        if states is not None and not all(s == "terminated" for s in states):
            left.append((instance_id, states))
    for profile_name, role_name in st["profiles"]:
        _drop_instance_profile(iam, profile_name, role_name)
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            left.append(("instance-profile", profile_name))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    for role_name in st["roles"]:
        _drop_role(iam, role_name)
        try:
            iam.get_role(RoleName=role_name)
            left.append(("role", role_name))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    for net in st["networks"]:
        _drop_network(ec2, net)
        if ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [net["vpc"]]}])["Vpcs"]:
            left.append(("vpc", net["vpc"]))
    return left


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Run Command script exiting 42 reports Status Failed, ResponseCode 42, its stderr and prior
    stdout, and a Failed summary with ErrorCount 1, while the same-host control exiting 0 succeeds.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudwatch-metrics.html
    """

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    # Teardown is in-band: waiting for termination exceeds the on_cleanup time cap.
    st: dict = {"instances": [], "profiles": [], "roles": [], "networks": []}
    try:
        instance_id = _launch_managed_instance(ctx, ssm, ec2, iam, st)
        _legs(ssm, instance_id)
    finally:
        st["leftovers"] = _teardown(ec2, iam, st)
    assert st["leftovers"] == [], (
        f"teardown could not remove everything the check created: {st['leftovers']!r}"
    )


def _launch_managed_instance(ctx, ssm, ec2, iam, st):
    """One SSM-managed EC2 instance, created in-check and proven Online."""
    role_name = ctx.unique_name("sim2real-behav-rcfail-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav run-command non-zero-exit instance role",
        Tags=_TAG,
    )
    st["roles"].append(role_name)
    ctx.on_cleanup(lambda: _drop_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)

    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_TAG)
    st["profiles"].append((profile_name, role_name))
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, profile_name, role_name))
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), (
        f"{_AL2023_AMI_PARAM} must resolve to an AMI id; got {ami!r}"
    )
    subnet_id, zone = _network(ctx, ec2, st)
    tag_spec = [
        {"ResourceType": rt, "Tags": _TAG + [{"Key": "Name", "Value": role_name}]}
        for rt in ("instance", "volume")
    ]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=tag_spec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=30,
        delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    # Registered before the registration poll so a host that never comes up is still terminated.
    st["instances"].append(instance_id)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == zone, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, "
        f"expected {zone!r}"
    )

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(
        _agent_view,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=300,
        interval_s=5.0,
        what=f"the SSM agent on {instance_id} coming Online",
    )
    assert info["ResourceType"] == "EC2Instance", (
        f"expected an EC2Instance-typed managed node, got {info!r}"
    )
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got "
        f"{info.get('PlatformType')!r}"
    )
    return instance_id


def _send(ssm, instance_id, script, comment):
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": script},
            TimeoutSeconds=120,
            Comment=comment,
        )
    )
    assert sent["Command"]["Status"] == "Pending", (
        f"a freshly accepted command must be Pending, got "
        f"{sent['Command']['Status']!r}"
    )
    return sent["Command"]["CommandId"]


def _await_invocation(ssm, command_id, instance_id):
    def _probe():
        try:
            return ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(
        _probe,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=180,
        interval_s=5.0,
        what=f"invocation {command_id} on {instance_id} reaching a terminal status",
    )


def _await_summary(ssm, command_id):
    return _poll(
        lambda: _call_with_retry(
            lambda: ssm.list_commands(CommandId=command_id)["Commands"][0]
        ),
        lambda c: c.get("Status") in _TERMINAL,
        timeout_s=120,
        interval_s=5.0,
        what=f"the summary of command {command_id} reaching a terminal status",
    )


def _legs(ssm, instance_id):
    """The failing command and its control, sent together and graded apart."""
    failing = [
        "set -uo pipefail",
        f'echo "{_STDOUT_MARKER}"',
        f'echo "{_STDERR_MARKER}" 1>&2',
        f"exit {_EXIT_CODE}",
    ]
    control = [
        "set -euo pipefail",
        f'echo "{_STDOUT_MARKER}"',
    ]
    # Both sent before either is polled, so the second wait overlaps the first.
    fail_id = _send(ssm, instance_id, failing, "sim2real-behav nonzero-exit")
    ok_id = _send(ssm, instance_id, control, "sim2real-behav nonzero-exit control")
    assert fail_id != ok_id, (
        f"two SendCommand calls must mint distinct command ids, both were {fail_id!r}"
    )

    bad = _await_invocation(ssm, fail_id, instance_id)
    assert bad["Status"] == "Failed", (
        f"a script exiting {_EXIT_CODE} must make the invocation Failed, not "
        f"{bad['Status']!r} (StatusDetails={bad.get('StatusDetails')!r}, "
        f"ResponseCode={bad.get('ResponseCode')!r})"
    )
    assert bad["ResponseCode"] == _EXIT_CODE, (
        f"ResponseCode must carry the script's exit status verbatim; expected "
        f"{_EXIT_CODE}, got {bad['ResponseCode']!r}"
    )
    assert _STDERR_MARKER in bad["StandardErrorContent"], (
        f"the agent must ship the script's stderr back; expected "
        f"{_STDERR_MARKER!r} inside StandardErrorContent, got "
        f"{bad['StandardErrorContent']!r}"
    )
    assert _STDOUT_MARKER in bad["StandardOutputContent"], (
        f"stdout written before a failing exit must not be discarded; expected "
        f"{_STDOUT_MARKER!r} inside StandardOutputContent, got "
        f"{bad['StandardOutputContent']!r}"
    )
    assert bad["InstanceId"] == instance_id, (
        f"the failed invocation reports instance {bad['InstanceId']!r}, expected "
        f"{instance_id!r}"
    )

    # The control: same host, same document, same instant — only the exit differs.
    good = _await_invocation(ssm, ok_id, instance_id)
    assert good["Status"] == "Success", (
        f"the control script exits 0 and must succeed on the same host; it was "
        f"{good['Status']!r} (StatusDetails={good.get('StatusDetails')!r}, "
        f"stderr={good.get('StandardErrorContent')!r})"
    )
    assert good["ResponseCode"] == 0, (
        f"the control's ResponseCode must be 0, got {good['ResponseCode']!r}"
    )
    assert good["StandardErrorContent"] == "", (
        f"the control writes nothing to stderr, got "
        f"{good['StandardErrorContent']!r}"
    )
    assert _STDOUT_MARKER in good["StandardOutputContent"], (
        f"the control's stdout must carry {_STDOUT_MARKER!r}, got "
        f"{good['StandardOutputContent']!r}"
    )

    # The command summaries, read via ListCommands, must disagree exactly as the invocations did.
    bad_cmd = _await_summary(ssm, fail_id)
    ok_cmd = _await_summary(ssm, ok_id)
    assert (
        bad_cmd["TargetCount"],
        bad_cmd["CompletedCount"],
        bad_cmd["ErrorCount"],
    ) == (1, 1, 1), (
        "the failing command's summary must report one target completed with one "
        "error; got "
        f"{(bad_cmd['TargetCount'], bad_cmd['CompletedCount'], bad_cmd['ErrorCount'])!r}"
    )
    assert bad_cmd["Status"] == "Failed", (
        f"the failing command's summary Status must be Failed, got "
        f"{bad_cmd['Status']!r}"
    )
    assert (
        ok_cmd["TargetCount"],
        ok_cmd["CompletedCount"],
        ok_cmd["ErrorCount"],
    ) == (1, 1, 0), (
        "the control command's summary must report one target completed with no "
        "errors; got "
        f"{(ok_cmd['TargetCount'], ok_cmd['CompletedCount'], ok_cmd['ErrorCount'])!r}"
    )
    assert ok_cmd["Status"] == "Success", (
        f"the control command's summary Status must be Success, got "
        f"{ok_cmd['Status']!r}"
    )

    # The failure is also visible through the list form, and agrees with the read.
    listed = []
    for page in ssm.get_paginator("list_command_invocations").paginate(
        CommandId=fail_id, Details=True
    ):
        listed += page["CommandInvocations"]
    assert len(listed) == 1, (
        f"exactly one invocation must exist for a single-target command, got {listed!r}"
    )
    assert listed[0]["Status"] == "Failed", (
        f"ListCommandInvocations must report the same Failed status as "
        f"GetCommandInvocation, got {listed[0]['Status']!r}"
    )

    # And a Failed invocation is still attributed to its own host only.
    stray = _error_code(
        lambda: ssm.get_command_invocation(
            CommandId=fail_id, InstanceId="i-00000000000000000"
        )
    )
    assert stray == (
        "InvocationDoesNotExist",
        f"Invocation not found for {fail_id}, i-00000000000000000",
    ), (
        "a failed invocation must exist only for the instance it targeted; asking for "
        f"another instance id must be refused, got {stray!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
