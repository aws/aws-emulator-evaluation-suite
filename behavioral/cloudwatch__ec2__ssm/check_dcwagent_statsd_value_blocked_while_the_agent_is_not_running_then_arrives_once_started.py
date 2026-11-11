"""dcwagent-statsd-value-blocked-while-the-agent-is-not-running-then-arrives-once-started."""
from __future__ import annotations

import base64
import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dcwagent-statsd-value-blocked-while-the-agent-is-not-running-then-arrives-once-started"
GROUP = 'cloudwatch-agent'
SERVICES = ['cloudwatch', 'ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_CW_AGENT_POLICY = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_AGENT_CTL = "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl"
_STATSD_PORT = 8125

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """The ClientError Error record (Code, Message) fn raised; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("the call was expected to be refused but it succeeded")


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
    """Poll probe() until predicate(result); AssertionError on timeout.

    A machine that launched and never converged is a FAIL, never an environment limitation.
    """
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
    """Delete, tolerating 'already gone' and retrying 'still referenced'.

    Every caller here terminates or revokes the referent FIRST (LIFO cleanup order), so this loop
    only absorbs the lag between the referent disappearing and EC2 admitting it.
    """
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
    """An AZ that is BOTH 'available' and offers instance_type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types. A hardcoded name is the same
    capacity gamble wearing a fixed label, because AZ names are per-account aliases.
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


def _network(ctx, scenario, cidr="10.174.0.0/16", subnet_cidr="10.174.1.0/24"):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Built rather than borrowed: a fresh account may have no default VPC and default subnets
    can be deleted, so a check that leaned on them would be asserting account configuration.
    Egress matters here beyond SSM registration — the guest has to reach the package repositories to
    install the agent and the CloudWatch endpoint to publish. Every resource is tagged in the SAME
    call that creates it: an untagged EC2 resource cannot be found by tag later.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
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

    # The VPC's own main route table, which is created with the VPC and destroyed with it.
    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"),
        gone=("InvalidRoute.NotFound", "InvalidRouteTableID.NotFound")))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-cwagent-"), VpcId=vpc_id,
        Description="sim2real cloudwatch-agent egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """A profile whose role can register with SSM and publish metrics as the agent.

    The permission to publish is deliberately PRESENT throughout this check: the one thing broken
    below is the agent process, so an absence that came from a missing permission would be a second
    variable and the check could not attribute the result.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cwagent-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real cloudwatch-agent managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        for arn in (_SSM_CORE_POLICY, _CW_AGENT_POLICY):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=arn)
            except ClientError as exc:
                if _code(exc) != "NoSuchEntity":
                    raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
    iam.attach_role_policy(RoleName=name, PolicyArn=_CW_AGENT_POLICY)

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
    """Terminate and wait for 'terminated' — not merely 'shutting-down'.

    The ENI and the root volume only go away at 'terminated', and the subnet, security group and
    VPC deletions registered EARLIER (and therefore running later, LIFO) all depend on that.
    """
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


def _launch(ctx, *, profile_name, subnet_id, sg_id, scenario):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
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


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=900, exec_timeout=600):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=exec_timeout,
        Comment="sim2real cloudwatch-agent in-guest"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=timeout_s, interval_s=5.0,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    return command_id, inv


def _marker(stdout, marker):
    """The text after `marker` on the LAST line that starts with it, or None.

    Anchored at the marker rather than split over the whole line so an extra word from the guest's
    own tooling cannot be read as the value.
    """
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _agent_config(namespace, interval=10):
    """The agent configuration this check installs, as the JSON the guest will be handed.

    `aggregation_dimensions` is the load-bearing part: it makes the agent publish every series
    rolled up on exactly InstanceId, so the dimension set this process later queries is one it
    CHOSE rather than one it has to discover. Discovery is the trap here — `list_metrics` lags the
    datapoints by many minutes, so anything that waits for a metric to appear in the catalogue
    measures the catalogue instead of the agent, and an ABSENCE read off the catalogue would be
    meaningless.
    """
    return {
        "agent": {"metrics_collection_interval": interval, "omit_hostname": True},
        "metrics": {
            "namespace": namespace,
            "append_dimensions": {"InstanceId": "${aws:InstanceId}"},
            "aggregation_dimensions": [["InstanceId"]],
            "metrics_collected": {
                "statsd": {
                    "service_address": f":{_STATSD_PORT}",
                    "metrics_collection_interval": interval,
                    "metrics_aggregation_interval": 0,
                },
            },
        },
    }


def _install_lines(config):
    """Guest lines that install the agent from the AL2023 repository and stage `config`.

    Nothing is started here: the configuration file is written and the daemon is explicitly left
    stopped, which is the single variable this check breaks.
    """
    blob = base64.b64encode(json.dumps(config).encode()).decode()
    return [
        f"echo {blob} | base64 -d > /tmp/cwagent.json",
        "dnf install -y amazon-cloudwatch-agent > /tmp/cwagent-install.log 2>&1",
        'echo "CWAGENT-RPM $(rpm -q amazon-cloudwatch-agent)"',
        "echo \"CWAGENT-INSTALL-TAIL $(tail -2 /tmp/cwagent-install.log | tr '\\n' ';')\"",
        # Explicit rather than assumed: whether the package's post-install starts the daemon is not
        # the subject, so the state is asserted into existence instead of inherited.
        f"{_AGENT_CTL} -a stop > /tmp/cwagent-stop.log 2>&1 || true",
    ]


# The listener is counted out of /proc rather than with `ss`, for two reasons: /proc/net/udp needs
# no package to be installed in the guest, and a Go daemon binding ":8125" dual-stack shows up in
# /proc/net/udp6 rather than /proc/net/udp, so both files are read. The port is the hex the kernel
# prints, derived rather than written out.
_STATUS_LINES = [
    'echo "CWAGENT-SYSTEMD $(systemctl is-active amazon-cloudwatch-agent)"',
    f"""echo "CWAGENT-CTL $({_AGENT_CTL} -a status | tr -d ' \\n'"""
    """ | grep -o '"status":"[a-z]*"' | head -1)\"""",
    f"""echo "CWAGENT-LISTEN $(cat /proc/net/udp /proc/net/udp6"""
    f""" | grep -ci ':{_STATSD_PORT:04X}')\"""",
]

_IMDS_LINES = [
    "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
    " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
    'echo "CWAGENT-IID $(curl -s -m 10 -H "X-aws-ec2-metadata-token: $TOK"'
    ' http://169.254.169.254/latest/meta-data/instance-id)"',
]


def _emit_lines(metric, value, repeats=6, interval=5):
    """The act: a StatsD datagram written from inside the guest to the agent's UDP listener.

    Repeated so a single lost datagram (UDP, by design) cannot decide the check — which matters in
    both directions here, because one leg asserts the value arrived and the other that it did not.
    """
    return [
        f'for _ in $(seq 1 {repeats}); do echo "{metric}:{value}|g"'
        f" > /dev/udp/127.0.0.1/{_STATSD_PORT}; sleep {interval}; done",
        f'echo "CWAGENT-SENT {value}"',
    ]


def _datapoints(cw, *, namespace, metric, instance_id, start, minutes=30):
    """Every datapoint for one series, queried on the dimension set the agent was told to publish.

    Scoped to a per-run namespace and this instance id, so 'empty' is a property of the query and
    not of what else happens to be running in a shared account — the whole absence leg rests
    on that.
    """
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start - datetime.timedelta(minutes=5),
        EndTime=start + datetime.timedelta(minutes=minutes),
        Period=60,
        Statistics=["Maximum", "Minimum", "SampleCount"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5", "timing:real-time",
)
def run(ctx) -> None:
    """A StatsD datagram sent inside the guest while the CloudWatch agent is NOT running reaches
    CloudWatch nowhere, while the same datagram arrives with its exact value once the agent is
    started; the absence is asserted only after that later value is read back."""
    scenario = "cwagent-agent-stopped-drops"
    namespace = ctx.unique_name("sim2real-cwagent-")
    # Derived per run, and distinct: a target that published both would pass neither leg.
    blocked_value = 5000 + int(uuid.uuid4().hex[:6], 16) % 1000
    delivered_value = 7000 + int(uuid.uuid4().hex[:6], 16) % 1000
    blocked_metric = "sim2real_dcwagent_blocked"
    delivered_metric = "sim2real_dcwagent_delivered"

    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")

    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario)
    instance_id = inst["InstanceId"]
    # Registered before the first wait: a host that never comes up must not strand a billing
    # instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    launched_at = datetime.datetime.now(datetime.timezone.utc)
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    info = _wait_online(ctx, instance_id)
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    # --- phase 1: the one broken thing — the daemon is not running ------------
    config = _agent_config(namespace)
    off_lines = (
        ["set -uo pipefail"]
        + _install_lines(config)
        + _STATUS_LINES
        + _IMDS_LINES
        + _emit_lines(blocked_metric, blocked_value)
    )
    command_id, off = _run_shell(ctx, instance_id, off_lines,
                                 what="emitting a gauge while the agent is stopped")
    off_out = off.get("StandardOutputContent", "")
    assert off["Status"] == "Success", (
        f"the stopped-agent invocation was {off['Status']!r}: {off.get('StatusDetails')!r} "
        f"stdout={off_out!r} stderr={off.get('StandardErrorContent')!r}"
    )
    rpm = _marker(off_out, "CWAGENT-RPM")
    assert rpm is not None and rpm.startswith("amazon-cloudwatch-agent-"), (
        f"the guest must report the installed agent package, got {rpm!r}; stdout was {off_out!r}"
    )
    assert _marker(off_out, "CWAGENT-IID") == instance_id, (
        f"the guest read its own instance id as {_marker(off_out, 'CWAGENT-IID')!r} from IMDSv2 "
        f"but RunInstances returned {instance_id!r} — this evidence is from another machine"
    )
    assert _marker(off_out, "CWAGENT-SYSTEMD") == "inactive", (
        "systemd inside the guest must report the agent unit inactive in this phase, got "
        f"{_marker(off_out, 'CWAGENT-SYSTEMD')!r} — the variable this check breaks was not broken"
    )
    assert _marker(off_out, "CWAGENT-CTL") == '"status":"stopped"', (
        "the agent's own control interface must report it stopped in this phase, got "
        f"{_marker(off_out, 'CWAGENT-CTL')!r}"
    )
    assert _marker(off_out, "CWAGENT-LISTEN") == "0", (
        f"the kernel inside the guest must show NO listener on :{_STATSD_PORT} while the agent is "
        f"stopped; /proc/net/udp{{,6}} counted {_marker(off_out, 'CWAGENT-LISTEN')!r}"
    )
    assert _marker(off_out, "CWAGENT-SENT") == str(blocked_value), (
        f"the guest must report sending {blocked_value}, got "
        f"{_marker(off_out, 'CWAGENT-SENT')!r}"
    )

    early = _datapoints(cw, namespace=namespace, metric=blocked_metric,
                        instance_id=instance_id, start=launched_at)
    assert early == [], (
        f"nothing can have published {blocked_metric!r} while no daemon held the socket, got "
        f"{early!r}"
    )

    # --- phase 2: the positive control, same everything but the daemon runs ---
    on_lines = (
        ["set -uo pipefail",
         f"{_AGENT_CTL} -a fetch-config -m ec2 -s -c file:/tmp/cwagent.json"
         " > /tmp/cwagent-fetch.log 2>&1",
         "echo \"CWAGENT-FETCH-TAIL $(tail -2 /tmp/cwagent-fetch.log | tr '\\n' ';')\"",
         "sleep 10"]
        + _STATUS_LINES
        + _emit_lines(delivered_metric, delivered_value, repeats=12)
    )
    _on_command_id, on = _run_shell(ctx, instance_id, on_lines,
                                    what="emitting a gauge once the agent is started")
    on_out = on.get("StandardOutputContent", "")
    assert on["Status"] == "Success", (
        f"the started-agent invocation was {on['Status']!r}: {on.get('StatusDetails')!r} "
        f"stdout={on_out!r} stderr={on.get('StandardErrorContent')!r}"
    )
    assert _marker(on_out, "CWAGENT-SYSTEMD") == "active", (
        "systemd inside the guest must report the agent unit active after fetch-config -s, got "
        f"{_marker(on_out, 'CWAGENT-SYSTEMD')!r}"
    )
    assert _marker(on_out, "CWAGENT-CTL") == '"status":"running"', (
        "the agent's own control interface must report it running in this phase, got "
        f"{_marker(on_out, 'CWAGENT-CTL')!r}"
    )
    assert int(_marker(on_out, "CWAGENT-LISTEN")) >= 1, (
        f"the started agent must hold a UDP socket on :{_STATSD_PORT}; the kernel inside the guest "
        f"counted {_marker(on_out, 'CWAGENT-LISTEN')!r} — the two phases would then differ in "
        "nothing observable"
    )
    assert _marker(on_out, "CWAGENT-SENT") == str(delivered_value), (
        f"the guest must report sending {delivered_value}, got "
        f"{_marker(on_out, 'CWAGENT-SENT')!r}"
    )

    points = _poll(
        lambda: _datapoints(cw, namespace=namespace, metric=delivered_metric,
                            instance_id=instance_id, start=launched_at),
        lambda p: len(p) >= 1,
        timeout_s=480, interval_s=15.0,
        what=f"the StatsD gauge {delivered_metric!r} becoming readable in {namespace!r}")
    values = {(p["Maximum"], p["Minimum"]) for p in points}
    assert values == {(float(delivered_value), float(delivered_value))}, (
        f"every datapoint of {delivered_metric!r} must carry exactly the value the guest emitted "
        f"({delivered_value}); CloudWatch served "
        f"{[(p['Timestamp'].isoformat(), p['Maximum'], p['Minimum']) for p in points]!r}"
    )

    # --- the effect's absence, asserted after the pipeline demonstrably ran ---
    late = _datapoints(cw, namespace=namespace, metric=blocked_metric,
                       instance_id=instance_id, start=launched_at)
    assert late == [], (
        f"{blocked_metric!r} must still be absent now that {delivered_metric!r} has been read back "
        f"from the same guest and namespace — a later datagram got through, so this one was "
        f"dropped by the stopped daemon rather than merely not flushed yet; got {late!r}"
    )

    # --- and the query that returned 'nothing' does validate its input --------
    # Without this, an implementation that answers 'no datapoints' to everything would satisfy the
    # absence assertions above for the wrong reason.
    bad_period = _error(lambda: cw.get_metric_statistics(
        Namespace=namespace, MetricName=blocked_metric,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=launched_at - datetime.timedelta(minutes=5),
        EndTime=launched_at + datetime.timedelta(minutes=30),
        Period=7, Statistics=["Maximum"]))
    assert bad_period.get("Code") == "InvalidParameterValue", (
        "GetMetricStatistics must refuse a period outside the permitted set rather than answer "
        f"emptily, got {bad_period!r}"
    )
    expected = "The parameter Period must be a value in the set [1, 5, 10, 20, 30]."
    assert bad_period.get("Message") == expected, (
        f"GetMetricStatistics must say {expected!r}, got {bad_period.get('Message')!r}")

    # --- the guest evidence is attributed to THIS host, not to the fleet ------
    stray = _error(lambda: ctx.client("ssm").get_command_invocation(
        CommandId=command_id, InstanceId="i-00000000000000000"))
    assert stray.get("Code") == "InvocationDoesNotExist", (
        "the in-guest output asserted above must exist only for the instance it ran on; asking for "
        f"another instance id must be refused, got {stray!r}"
    )
    expected = f"Invocation not found for {command_id}, i-00000000000000000"
    assert stray.get("Message") == expected, (
        f"GetCommandInvocation must say {expected!r}, got {stray.get('Message')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
