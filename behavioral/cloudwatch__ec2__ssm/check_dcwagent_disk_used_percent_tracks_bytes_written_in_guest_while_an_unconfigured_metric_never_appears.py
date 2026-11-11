"""dcwagent-disk-used-percent-tracks-bytes-written-in-guest-while-an-unconfigured-metric-never-appears."""
from __future__ import annotations

import base64
import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dcwagent-disk-used-percent-tracks-bytes-written-in-guest-while-an-unconfigured-metric-never-appears"
GROUP = 'cloudwatch-agent'
SERVICES = ['cloudwatch', 'ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_CW_AGENT_POLICY = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_AGENT_CTL = "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl"


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
    """Delete, tolerating 'already gone' and retrying 'still referenced'.

    Absorbs the lag between the referent disappearing and EC2 admitting it.
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

    Neither API alone reports both, and AZ names are per-account aliases.
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


def _network(ctx, scenario, cidr="10.175.0.0/16", subnet_cidr="10.175.1.0/24"):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Egress lets the guest reach SSM, the package repositories and the CloudWatch endpoint.
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

    Publishing is allowed even for the metric proved absent, so only the configuration excludes it.
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
    """Terminate and wait for 'terminated'; the ENI and root volume only go away then."""
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
    """The text after `marker` on the LAST line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _agent_config(namespace, interval=10):
    """The agent configuration: the root filesystem only, published on the InstanceId dimension.

    Pinning the dimension avoids list_metrics lag; `mem` is omitted so the absence leg rests on it.
    """
    return {
        "agent": {"metrics_collection_interval": interval, "omit_hostname": True},
        "metrics": {
            "namespace": namespace,
            "append_dimensions": {"InstanceId": "${aws:InstanceId}"},
            "aggregation_dimensions": [["InstanceId"]],
            "metrics_collected": {
                "disk": {
                    "measurement": ["disk_used_percent"],
                    "resources": ["/"],
                    "metrics_collection_interval": interval,
                },
            },
        },
    }


def _install_lines(config):
    """Guest lines that install the agent from the AL2023 repository and start it on `config`.

    The configuration travels as base64 to avoid two layers of shell quoting.
    """
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


_STATUS_LINES = [
    'echo "CWAGENT-SYSTEMD $(systemctl is-active amazon-cloudwatch-agent)"',
    f"""echo "CWAGENT-CTL $({_AGENT_CTL} -a status | tr -d ' \\n'"""
    """ | grep -o '"status":"[a-z]*"' | head -1)\"""",
]

_IMDS_LINES = [
    "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
    " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
    'echo "CWAGENT-IID $(curl -s -m 10 -H "X-aws-ec2-metadata-token: $TOK"'
    ' http://169.254.169.254/latest/meta-data/instance-id)"',
]


_DF_LINE = 'echo "CWAGENT-DF-{when} $(df --output=pcent / | tail -1 | tr -dc 0-9.)"'


def _df_line(when):
    """The guest's OWN reading of how full its root filesystem is, as a bare percentage."""
    return _DF_LINE.format(when=when)


def _fill_lines(path, gib):
    """Write real bytes to the guest's root filesystem and report what the guest then sees.

    `fallocate` reserves blocks rather than writing a sparse file, so the disk really fills.
    """
    return [
        f"fallocate -l {gib}G {path}",
        "sync",
        f'echo "CWAGENT-FILL-BYTES $(stat -c %s {path})"',
        _df_line("AFTER"),
    ]


def _datapoints(cw, *, namespace, metric, instance_id, start, minutes=30):
    """Every datapoint for one series, queried on the dimension set the agent was told to publish.

    Scoped to a per-run namespace and this instance id, so 'empty' is a property of the query.
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


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5", "timing:real-time",
)
def run(ctx) -> None:
    """Writing 2 GiB in the guest raises the agent's published disk_used_percent above baseline and
    to within five points of the guest's own `df`, while an unconfigured metric never appears.
    """
    scenario = "cwagent-disk-tracks-guest"
    namespace = ctx.unique_name("sim2real-cwagent-")
    fill_path = "/var/tmp/sim2real-cwagent-fill"
    fill_gib = 2
    unconfigured_metric = "mem_used_percent"

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

    # --- install and start the agent; read the guest's own baseline -----------
    setup_lines = (
        ["set -uo pipefail"]
        + _install_lines(_agent_config(namespace))
        + ["sleep 10"]
        + _STATUS_LINES
        + _IMDS_LINES
        + [
            _df_line("BEFORE"),
            'echo "CWAGENT-AVAIL-MB $(df --output=avail -m / | tail -1 | tr -dc 0-9)"',
        ]
    )
    command_id, setup = _run_shell(ctx, instance_id, setup_lines,
                                  what="installing the CloudWatch agent with a disk-only config")
    out = setup.get("StandardOutputContent", "")
    assert setup["Status"] == "Success", (
        f"the install invocation was {setup['Status']!r}: {setup.get('StatusDetails')!r} "
        f"stdout={out!r} stderr={setup.get('StandardErrorContent')!r}"
    )
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
    assert _marker(out, "CWAGENT-IID") == instance_id, (
        f"the guest read its own instance id as {_marker(out, 'CWAGENT-IID')!r} from IMDSv2 but "
        f"RunInstances returned {instance_id!r} -- this evidence is from another machine"
    )
    df_before = float(_marker(out, "CWAGENT-DF-BEFORE"))
    assert 0.0 < df_before < 100.0, (
        f"the guest's own df reading of / is not a percentage: {df_before!r}"
    )
    avail_mb = float(_marker(out, "CWAGENT-AVAIL-MB"))
    assert avail_mb > fill_gib * 1024 * 1.5, (
        f"the guest reports only {avail_mb!r} MiB free on /, too little for this check to write "
        f"{fill_gib} GiB and leave the machine usable"
    )

    # --- the baseline the published series starts from ------------------------
    baseline = _poll(
        lambda: _datapoints(cw, namespace=namespace, metric="disk_used_percent",
                            instance_id=instance_id, start=launched_at),
        lambda p: len(p) >= 1,
        timeout_s=480, interval_s=15.0,
        what=f"disk_used_percent becoming readable in namespace {namespace!r}")
    baseline_max = max(p["Maximum"] for p in baseline)
    assert abs(baseline_max - df_before) <= 5.0, (
        f"the agent published disk_used_percent={baseline_max!r} while df inside the guest reported "
        f"{df_before!r}% for / in the same window -- the published number is not this filesystem"
    )

    # --- the act: real bytes on the guest's filesystem ------------------------
    fill_at = datetime.datetime.now(datetime.timezone.utc)
    _fill_command_id, fill = _run_shell(
        ctx, instance_id, ["set -uo pipefail"] + _fill_lines(fill_path, fill_gib),
        what=f"writing {fill_gib} GiB inside the guest")
    fill_out = fill.get("StandardOutputContent", "")
    assert fill["Status"] == "Success", (
        f"the fill invocation was {fill['Status']!r}: {fill.get('StatusDetails')!r} "
        f"stdout={fill_out!r} stderr={fill.get('StandardErrorContent')!r}"
    )
    # Removed from inside the guest rather than left to termination, so a machine that outlives the
    # check for any reason is not sitting at a falsified disk level.
    ctx.on_cleanup(lambda: _run_shell(ctx, instance_id, ["rm -f " + fill_path],
                                      what="removing the fill file"))
    assert int(_marker(fill_out, "CWAGENT-FILL-BYTES")) == fill_gib * 1024 ** 3, (
        f"the guest must hold a {fill_gib} GiB file after fallocate; stat reported "
        f"{_marker(fill_out, 'CWAGENT-FILL-BYTES')!r} bytes"
    )
    df_after = float(_marker(fill_out, "CWAGENT-DF-AFTER"))
    assert df_after > df_before, (
        f"df inside the guest must show / fuller after writing {fill_gib} GiB: it reported "
        f"{df_before!r}% before and {df_after!r}% after"
    )

    # --- the effect: the published series follows the guest's filesystem ------
    minute = fill_at.replace(second=0, microsecond=0)
    after = _poll(
        lambda: [p for p in _datapoints(cw, namespace=namespace, metric="disk_used_percent",
                                        instance_id=instance_id, start=launched_at)
                 if p["Timestamp"] >= minute and p["Maximum"] > baseline_max],
        lambda p: len(p) >= 1,
        timeout_s=480, interval_s=15.0,
        what=(f"disk_used_percent rising above its {baseline_max!r} baseline in a datapoint "
              f"timestamped at or after {minute.isoformat()}"))
    risen = max(p["Maximum"] for p in after)
    assert risen > baseline_max, (
        f"the published disk_used_percent must exceed the pre-fill baseline {baseline_max!r}; the "
        f"highest post-fill datapoint was {risen!r}"
    )
    assert abs(risen - df_after) <= 5.0, (
        f"the agent published {risen!r} after the fill while df inside the guest reported "
        f"{df_after!r}% -- the published number tracks something other than this filesystem"
    )

    # --- the absence: a metric the configuration never asked for --------------
    # Asserted only after the disk increase was read back, so the pipeline is known to deliver.
    unconfigured = _datapoints(cw, namespace=namespace, metric=unconfigured_metric,
                               instance_id=instance_id, start=launched_at)
    assert unconfigured == [], (
        f"{unconfigured_metric!r} must not be published by an agent whose configuration collects "
        "only the root filesystem -- disk_used_percent from the same daemon, guest and namespace "
        f"has just been read back, so the pipeline was delivering; got {unconfigured!r}"
    )

    # --- the guest evidence is attributed to THIS host, not to another one ----
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
