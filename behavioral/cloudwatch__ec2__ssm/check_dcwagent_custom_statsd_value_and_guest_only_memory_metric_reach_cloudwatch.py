"""dcwagent-custom-statsd-value-and-guest-only-memory-metric-reach-cloudwatch."""
from __future__ import annotations

import base64
import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dcwagent-custom-statsd-value-and-guest-only-memory-metric-reach-cloudwatch"
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
    """Delete, tolerating 'already gone' and retrying 'still referenced' while EC2 catches up
    with a referent that cleanup has already removed."""
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
    """An AZ that is both 'available' and offers instance_type; neither describe call reports
    both, and AZ names are per-account aliases, so none is hardcoded."""
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


def _network(ctx, scenario, cidr="10.173.0.0/16", subnet_cidr="10.173.1.0/24"):
    """A dedicated VPC with one public subnet and an egress-only security group, since an account
    may have no default VPC. The guest needs egress for the package repository and CloudWatch."""
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
    """A profile whose role can register with SSM and publish metrics as the agent."""
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
    """Terminate and wait for 'terminated', not 'shutting-down': the ENI and root volume only go
    away then, and the later subnet, security group and VPC deletions depend on that."""
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


def _launch(ctx, *, profile_name, subnet_id, sg_id, scenario, detailed_monitoring=False):
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
            Monitoring={"Enabled": detailed_monitoring},
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
    """The text after `marker` on the last line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _agent_config(namespace, interval=10):
    """The agent configuration the guest is handed. aggregation_dimensions pins every series to
    exactly InstanceId so datapoints are queried directly; list_metrics lags them by minutes."""
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
                "mem": {
                    "measurement": ["mem_used_percent"],
                    "metrics_collection_interval": interval,
                },
            },
        },
    }


def _install_lines(config):
    """Guest lines that install the agent from the AL2023 repository and start it on `config`;
    the config travels as base64 to survive shell quoting."""
    blob = base64.b64encode(json.dumps(config).encode()).decode()
    return [
        f"echo {blob} | base64 -d > /tmp/cwagent.json",
        "dnf install -y amazon-cloudwatch-agent > /tmp/cwagent-install.log 2>&1",
        'echo "CWAGENT-RPM $(rpm -q amazon-cloudwatch-agent)"',
        "echo \"CWAGENT-INSTALL-TAIL $(tail -2 /tmp/cwagent-install.log | tr '\\n' ';')\"",
        f"{_AGENT_CTL} -a fetch-config -m ec2 -s -c file:/tmp/cwagent.json"
        " > /tmp/cwagent-fetch.log 2>&1",
        "echo \"CWAGENT-FETCH-TAIL $(tail -2 /tmp/cwagent-fetch.log | tr '\\n' ';')\"",
    ]


_IMDS_LINES = [
    "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
    " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
    'echo "CWAGENT-IID $(curl -s -m 10 -H "X-aws-ec2-metadata-token: $TOK"'
    ' http://169.254.169.254/latest/meta-data/instance-id)"',
]

# The guest's own reading of the quantity the hypervisor cannot see, computed the way the agent's
# mem plugin computes it (total minus free, buffers and cache) rather than from MemAvailable.
_GUEST_MEM_LINE = (
    """echo "CWAGENT-GUEST-MEM $(awk '/^MemTotal:/{t=$2}/^MemFree:/{f=$2}/^Buffers:/{b=$2}"""
    """/^Cached:/{c=$2} END{printf "%.2f", (t-f-b-c)/t*100}' /proc/meminfo)\""""
)

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


def _emit_lines(metric, value, repeats=12, interval=5):
    """StatsD datagrams written in the guest to the agent's UDP listener, repeated across a minute
    so a whole period carries the value and one lost datagram cannot decide the check."""
    return [
        f'for _ in $(seq 1 {repeats}); do echo "{metric}:{value}|g"'
        f" > /dev/udp/127.0.0.1/{_STATSD_PORT}; sleep {interval}; done",
        f'echo "CWAGENT-SENT {value}"',
    ]


def _datapoints(cw, *, namespace, metric, instance_id, start, minutes=30):
    """Every datapoint for one series in the per-run namespace, on the InstanceId dimension."""
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start - datetime.timedelta(minutes=5),
        EndTime=start + datetime.timedelta(minutes=minutes),
        Period=60,
        Statistics=["Maximum", "Minimum", "Average", "SampleCount"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """The CloudWatch agent installed in an EC2 guest publishes a per-run StatsD gauge exactly,
    and a mem_used_percent close to the guest's /proc/meminfo, which AWS/EC2 does not publish.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-custom-metrics-statsd.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/metrics-collected-by-CloudWatch-agent.html
    """
    scenario = "cwagent-custom-metric"
    namespace = ctx.unique_name("sim2real-cwagent-")
    # Derived per run: a target that hardcoded a plausible gauge value cannot pass.
    gauge_value = 3000 + int(uuid.uuid4().hex[:6], 16) % 1000
    gauge_metric = "sim2real_dcwagent_gauge"

    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")

    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    # Detailed monitoring: the positive control for the absence leg is a hypervisor metric for THIS
    # instance, and a 1-minute period is what makes it observable inside the check's budget.
    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario, detailed_monitoring=True)
    instance_id = inst["InstanceId"]
    # Registered before the first wait: a host that never comes up must not strand a billing
    # instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    launched_at = datetime.datetime.now(datetime.timezone.utc)
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )
    assert inst["Monitoring"]["State"] in ("enabled", "pending"), (
        f"detailed monitoring must be on at launch, got {inst['Monitoring']!r}"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    info = _wait_online(ctx, instance_id)
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    # --- install, configure, start, and emit from inside the guest -------------
    config = _agent_config(namespace)
    lines = (
        ["set -uo pipefail"]
        + _install_lines(config)
        + ["sleep 10"]
        + _STATUS_LINES
        + _IMDS_LINES
        + _emit_lines(gauge_metric, gauge_value)
        + [_GUEST_MEM_LINE]
    )
    command_id, inv = _run_shell(ctx, instance_id, lines,
                                 what="installing the CloudWatch agent and emitting a gauge")

    out = inv.get("StandardOutputContent", "")
    assert inv["Status"] == "Success", (
        f"the in-guest install/emit invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={out!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"ResponseCode was {inv['ResponseCode']!r}, stderr={inv.get('StandardErrorContent')!r}"
    )

    # --- guest-verified: the agent really is installed, running and listening ---
    rpm = _marker(out, "CWAGENT-RPM")
    assert rpm is not None and rpm.startswith("amazon-cloudwatch-agent-"), (
        f"the guest must report the installed agent package, got {rpm!r}; stdout was {out!r}"
    )
    assert _marker(out, "CWAGENT-SYSTEMD") == "active", (
        "systemd inside the guest must report the agent unit active after fetch-config -s, got "
        f"{_marker(out, 'CWAGENT-SYSTEMD')!r}"
    )
    assert _marker(out, "CWAGENT-CTL") == '"status":"running"', (
        "the agent's own control interface must report it running, got "
        f"{_marker(out, 'CWAGENT-CTL')!r}"
    )
    assert int(_marker(out, "CWAGENT-LISTEN")) >= 1, (
        f"the running agent must hold a UDP socket on :{_STATSD_PORT} inside the guest, but the "
        f"kernel's own socket tables count {_marker(out, 'CWAGENT-LISTEN')!r}; without a listener "
        "the datagram below would be dropped and nothing would say so"
    )
    assert _marker(out, "CWAGENT-IID") == instance_id, (
        f"the guest read its own instance id as {_marker(out, 'CWAGENT-IID')!r} from IMDSv2 but "
        f"RunInstances returned {instance_id!r} — the evidence below is from another machine"
    )
    assert _marker(out, "CWAGENT-SENT") == str(gauge_value), (
        f"the guest must report sending {gauge_value}, got {_marker(out, 'CWAGENT-SENT')!r}"
    )
    guest_mem = float(_marker(out, "CWAGENT-GUEST-MEM"))
    assert 0.0 < guest_mem < 100.0, (
        f"the guest's own /proc/meminfo reading is not a percentage: {guest_mem!r}"
    )

    # --- the effect: that exact value is readable in CloudWatch ---------------
    points = _poll(
        lambda: _datapoints(cw, namespace=namespace, metric=gauge_metric,
                            instance_id=instance_id, start=launched_at),
        lambda p: len(p) >= 1,
        timeout_s=480, interval_s=15.0,
        what=f"the StatsD gauge {gauge_metric!r} becoming readable in namespace {namespace!r}")
    # Maximum and Minimum over every datapoint make this an exact-value claim, not a range.
    values = {(p["Maximum"], p["Minimum"]) for p in points}
    assert values == {(float(gauge_value), float(gauge_value))}, (
        f"every datapoint of {gauge_metric!r} must carry exactly the value the guest emitted "
        f"({gauge_value}); CloudWatch served {[(p['Timestamp'].isoformat(), p['Maximum'], p['Minimum']) for p in points]!r}"
    )
    assert all(p["SampleCount"] >= 1.0 for p in points), (
        f"a datapoint with no samples is not a datapoint: {points!r}"
    )

    # --- the reason the agent exists: a metric the hypervisor cannot see -------
    mem_points = _poll(
        lambda: _datapoints(cw, namespace=namespace, metric="mem_used_percent",
                            instance_id=instance_id, start=launched_at),
        lambda p: len(p) >= 1,
        timeout_s=300, interval_s=15.0,
        what=f"mem_used_percent becoming readable in namespace {namespace!r}")
    agent_mem = mem_points[-1]["Average"]
    assert 0.0 < agent_mem < 100.0, (
        f"mem_used_percent must be a percentage of the guest's memory, got {agent_mem!r}"
    )
    # A tolerance, not an equality: the two readings are seconds apart on a live machine, and the
    # agent's plugin and this awk agree on the definition, not on the instant.
    assert abs(agent_mem - guest_mem) <= 25.0, (
        f"the agent published mem_used_percent={agent_mem!r} while the guest read {guest_mem!r} "
        "from /proc/meminfo in the same invocation — the published number is not this guest's "
        "memory"
    )

    # --- and its absence on the hypervisor's side of the boundary -------------
    hypervisor_mem = cw.get_metric_statistics(
        Namespace="AWS/EC2", MetricName="mem_used_percent",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=launched_at - datetime.timedelta(minutes=5),
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        Period=60, Statistics=["Maximum"])["Datapoints"]
    assert hypervisor_mem == [], (
        "AWS/EC2 must publish no memory metric for this instance — that gap is the entire reason "
        f"the agent exists; got {hypervisor_mem!r}"
    )
    # Positive control for that absence: the hypervisor IS reporting on this instance.
    cpu = _poll(
        lambda: cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=launched_at - datetime.timedelta(minutes=5),
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            Period=60, Statistics=["Maximum"])["Datapoints"],
        lambda d: len(d) >= 1, timeout_s=420, interval_s=20.0,
        what=f"AWS/EC2 CPUUtilization for {instance_id} (the absence leg's positive control)")
    assert all(0.0 <= d["Maximum"] <= 100.0 for d in cpu), (
        f"CPUUtilization must be a percentage: {cpu!r}"
    )

    # --- the guest evidence is attributed to THIS host ------------------------
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
