"""dtgthealth-guest-stalled-health-response-times-out-and-withdraws-the-target."""
from __future__ import annotations

import base64
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dtgthealth-guest-stalled-health-response-times-out-and-withdraws-the-target"
GROUP = 'dtgthealth-data-plane'
SERVICES = ['ec2', 'elbv2', 'ssm']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_INSTANCE_TYPE = "t3.micro"
_AL2023_SSM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: Two servers in one guest, on two ports, registered as two targets of one group. Two targets are
#: required: a group with every target unhealthy fails open and keeps routing.
_PORT_A = 80
_PORT_B = 8080
#: The minimum ALB health-check interval and thresholds, so a transition is observable in tens of
#: seconds rather than minutes.
_HC_INTERVAL_S = 5
_HC_TIMEOUT_S = 2
_HC_THRESHOLD = 2

# How long server B sits on a /health request when stalled: greater than _HC_TIMEOUT_S so the load
# balancer abandons the probe, yet finite so the server is slow rather than dead.
_STALL_S = 8
#: Requests per traffic burst; enough that round-robin over two targets reaches both.
_BURST = 12
_GUEST_ROOT = "/opt/sim2real"
#: The two guest servers' names, which each server also writes into its response body.
_NAME_A = "A"
_NAME_B = "B"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
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
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _retry_delete(fn, retries=36, delay=5.0):
    """Delete, retrying for a bounded time through the DependencyViolation window a terminating ENI
    or a deleting load balancer leaves behind."""
    gone = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidRouteTableID.NotFound",
            "InvalidInternetGatewayID.NotFound", "InvalidAssociationID.NotFound",
            "InvalidGroup.NotFound", "Gateway.NotAttached", "LoadBalancerNotFound",
            "TargetGroupNotFound", "ListenerNotFound")
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in gone:
                return None
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency",
                              "ResourceInUse") and attempt < retries - 1:
                time.sleep(delay)
                continue
            raise


def _usable_azs(ec2, n, instance_type=_INSTANCE_TYPE):
    """`n` AZs that are both 'available' and offer the instance type.

    describe_instance_type_offerings does not report zone state, so both calls are intersected.
    """
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert len(usable) >= n, (
        f"an application load balancer needs {n} availability zones that also offer "
        f"{_INSTANCE_TYPE!r}; this region intersected to {usable!r} (offered: {sorted(offered)!r})"
    )
    return usable[:n]


def _public_vpc(ctx, ec2, azs, scenario):
    """A VPC of this check's own making, with one public subnet per AZ.

    DNS resolution is enabled explicitly because the guest reaches the load balancer by DNS name.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario},
                                              {"Key": "Name", "Value": scenario}]}]

    second = random.randint(64, 191)
    vpc = ec2.create_vpc(CidrBlock=f"10.{second}.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    # The VPC's own main route table, so there is no association to create or tear down: it is
    # deleted with the VPC. The SSM agent needs this egress to register with its endpoint.
    rtb = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)

    subnets = []
    for i, az in enumerate(azs, start=1):
        subnet = ec2.create_subnet(
            VpcId=vpc, CidrBlock=f"10.{second}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet: _retry_delete(lambda: ec2.delete_subnet(SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
        subnets.append(subnet)
    return vpc, subnets


def _shared_sg(ctx, ec2, vpc, scenario):
    """One security group with a self-referencing ingress rule, worn by both load balancer and
    instance, so the load balancer reaches both guest ports and the guest reaches the load balancer.
    """
    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dtgth-sg-"), VpcId=vpc,
        Description="sim2real-dtgth alb and guest listener ports",
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name", "Value": scenario}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg)))
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
                        "UserIdGroupPairs": [{"GroupId": sg}]}
                       for p in (_PORT_A, _PORT_B)],
    )
    return sg


def _instance_profile(ctx, iam, scenario):
    role = ctx.unique_name("sim2real-dtgth-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-dtgth guest run-command role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    # IAM exposes no condition that reports an instance profile is usable by EC2; the bounded
    # RunInstances retry below waits for it.
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


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
    """Terminate and wait for 'terminated', not merely 'shutting-down': until then the ENI holds the
    security group and subnet, and their deletes fail with DependencyViolation."""
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


def _launch(ctx, ec2, ssm, subnet, sg, profile, scenario):
    """Launch one instance, tagged in the creating call, with termination registered immediately.

    The AMI comes from the SSM public parameter because image ids are region-specific and go stale.
    """
    ami = ssm.get_parameter(Name=_AL2023_SSM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_SSM} did not resolve to an AMI: {ami!r}"
    kv = [{"Key": "sim2real", "Value": scenario}, {"Key": "Name", "Value": scenario}]

    def _run():
        return ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            SecurityGroupIds=[sg], IamInstanceProfile={"Name": profile},
            TagSpecifications=[{"ResourceType": "instance", "Tags": kv},
                               {"ResourceType": "volume", "Tags": kv}],
        )["Instances"][0]

    # The propagation codes are the bounded retry that waits for the new instance profile.
    instance = _call_with_retry(
        _run, codes=_THROTTLE + ("InvalidParameterValue", "InvalidIamInstanceProfile.NotFound"),
        retries=30, delay=5.0)
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    return instance_id


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry is the wait for the agent: an unregistered host rejects it with
    InvalidInstanceId. The script is base64-encoded to avoid quoting it through the JSON list.
    """
    payload = base64.b64encode(("set -u\n" + script).encode()).decode()
    commands = [
        f"echo {payload} | base64 -d > /tmp/sim2real-dtgth-step.sh",
        "bash /tmp/sim2real-dtgth-step.sh",
    ]
    deadline = time.monotonic() + ready_timeout_s
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands}, TimeoutSeconds=600,
                Comment="sim2real-dtgth guest step",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=run_timeout_s, interval_s=5.0,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"{what}: the guest script was {inv['Status']!r} ({inv.get('StatusDetails')!r}); "
        f"rc={inv.get('ResponseCode')!r} stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _labels(stdout):
    """Single-valued `KEY=VALUE` lines of a guest script's stdout, as a dict (last value wins).

    Repeated `HIT=` lines are read by `_hits` instead.
    """
    out = {}
    for line in stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def _hits(stdout):
    """Every response body a burst brought back, in order; empty means the guest never reached the
    load balancer."""
    return [line.partition("=")[2].strip()
            for line in stdout.splitlines() if line.startswith("HIT=")]


def _server_source():
    """The in-guest HTTP server, which can be told to stall its /health answer past the timeout.

    Each request is logged on arrival, before any stall, so an abandoned probe is still counted;
    only /health stalls, while /app is always answered at full speed.
    """
    return (
        "import os, sys, time\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        "PORT = int(sys.argv[1]); NAME = sys.argv[2]; ROOT = sys.argv[3]\n"
        "STATE = os.path.join(ROOT, 'state-' + NAME)\n"
        "LOG = os.path.join(ROOT, 'log-' + NAME)\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    protocol_version = 'HTTP/1.1'\n"
        "    def do_GET(self):\n"
        "        path = self.path.split('?')[0]\n"
        "        try:\n"
        "            state = open(STATE).read().strip()\n"
        "        except OSError:\n"
        "            state = 'MISSING'\n"
        "        with open(LOG, 'a') as fh:\n"
        "            fh.write('%s %s %s\\n' % (NAME, path, state))\n"
        "        if path == '/health' and state == 'STALL':\n"
        f"            time.sleep({_STALL_S})\n"
        "        body = (('HEALTH-' if path == '/health' else 'BODY-') + NAME).encode()\n"
        "        try:\n"
        "            self.send_response(200)\n"
        "            self.send_header('Content-Type', 'text/plain')\n"
        "            self.send_header('Content-Length', str(len(body)))\n"
        "            self.end_headers()\n"
        "            self.wfile.write(body)\n"
        "        except OSError:\n"
        "            pass\n"
        "    def log_message(self, *a):\n"
        "        pass\n"
        "ThreadingHTTPServer(('0.0.0.0', PORT), H).serve_forever()\n"
    )


def _unit_source(name, port):
    return (
        "[Unit]\n"
        f"Description=sim2real-dtgth guest server {name}\n"
        "[Service]\n"
        f"ExecStart=/usr/bin/python3 {_GUEST_ROOT}/srv.py {port} {name} {_GUEST_ROOT}\n"
        "Restart=always\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _unit(name):
    """The systemd unit name for a server."""
    return f"sim2real-dtgth-{name.lower()}.service"


def _state_path(name):
    return f"{_GUEST_ROOT}/state-{name}"


def _log_path(name):
    return f"{_GUEST_ROOT}/log-{name}"


def _deploy_script():
    """Install and start both guest servers, then report their /health status over loopback."""
    srv = base64.b64encode(_server_source().encode()).decode()
    script = [f"mkdir -p {_GUEST_ROOT}", f"echo {srv} | base64 -d > {_GUEST_ROOT}/srv.py"]
    for name, port in ((_NAME_A, _PORT_A), (_NAME_B, _PORT_B)):
        unit = base64.b64encode(_unit_source(name, port).encode()).decode()
        script += [
            f"printf 'OK\\n' > {_state_path(name)}",
            f": > {_log_path(name)}",
            f"echo {unit} | base64 -d > /etc/systemd/system/{_unit(name)}",
        ]
    script += [
        "systemctl daemon-reload",
        f"systemctl enable --now {_unit(_NAME_A)} {_unit(_NAME_B)}",
        # Poll for both listeners over loopback, so a server that never starts fails here rather
        # than later as a load-balancer health failure.
        "for i in $(seq 1 30); do",
        f"  curl -s -o /dev/null --max-time 2 http://127.0.0.1:{_PORT_A}/health && \\",
        f"    curl -s -o /dev/null --max-time 2 http://127.0.0.1:{_PORT_B}/health && break",
        "  sleep 2",
        "done",
        f'echo "UNIT-{_NAME_A}=$(systemctl is-active {_unit(_NAME_A)})"',
        f'echo "UNIT-{_NAME_B}=$(systemctl is-active {_unit(_NAME_B)})"',
    ]
    return "\n".join(script) + "\n" + _local_health_lines()


def _local_health_lines():
    """Guest-local /health status codes over loopback, labelled."""
    return "".join(
        f"echo \"LOCAL-{name}=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 "
        f"http://127.0.0.1:{port}/health)\"\n"
        for name, port in ((_NAME_A, _PORT_A), (_NAME_B, _PORT_B))
    )


def _probe_timing_lines():
    """Whether each server answers /health over loopback within the health-check timeout."""
    return "".join(
        f"curl -s -o /dev/null --max-time {_HC_TIMEOUT_S} http://127.0.0.1:{port}/health "
        f"&& echo \"FAST-{name}=yes\" || echo \"FAST-{name}=no\"\n"
        for name, port in ((_NAME_A, _PORT_A), (_NAME_B, _PORT_B))
    )


def _counter_lines():
    """Per-server /app and /health request counts, read from the guest's own access logs."""
    lines = []
    for name in (_NAME_A, _NAME_B):
        lines.append(
            f"echo \"APP-{name}=$(awk '$2 ~ /^\\/app/ {{n++}} END {{print n+0}}' "
            f"{_log_path(name)})\"\n"
        )
        # A regex rather than a string equality, so the awk program contains no double quote: it
        # travels inside a double-quoted shell string.
        lines.append(
            f"echo \"HC-{name}=$(awk '$2 ~ /^\\/health$/ {{n++}} END {{print n+0}}' "
            f"{_log_path(name)})\"\n"
        )
    return "".join(lines)


def _burst_script(dns, token, rounds=1):
    """Fire `_BURST` requests per round at the load balancer from inside the guest, echoing each
    response body, then report the guest's own request counters.
    """
    return (
        f"for r in $(seq 1 {rounds}); do\n"
        f"  for i in $(seq 1 {_BURST}); do\n"
        f"    echo \"HIT=$(curl -s --max-time 5 http://{dns}/app-{token} || echo CURL-FAILED)\"\n"
        "  done\n"
        "done\n"
        + _counter_lines()
    )


def _create_alb(ctx, elb, subnets, sg, scenario):
    """An internal application load balancer, so the whole data path stays inside the VPC."""
    lb = elb.create_load_balancer(
        Name=ctx.unique_name("sim2real-dtgth-lb-"), Subnets=subnets, SecurityGroups=[sg],
        Scheme="internal", Type="application", IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elb, arn))
    state = _poll(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"][
            "Code"],
        lambda s: s == "active", timeout_s=600, interval_s=10.0,
        what=f"load balancer {arn} reaching 'active'")
    assert state == "active", f"load balancer state {state!r}, expected 'active'"
    return lb["DNSName"], arn


def _delete_lb_and_wait(elb, arn, timeout_s=420):
    """Delete the load balancer and wait for it to vanish: its network interfaces hold the shared
    security group until then."""
    _retry_delete(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elb.describe_load_balancers(LoadBalancerArns=[arn])
        except ClientError as exc:
            if _code(exc) == "LoadBalancerNotFound":
                return
            raise
        time.sleep(5)


def _create_target_group(ctx, elb, vpc, scenario):
    tg = elb.create_target_group(
        Name=ctx.unique_name("sim2real-dtgth-tg-"), Protocol="HTTP", Port=_PORT_A, VpcId=vpc,
        TargetType="instance", HealthCheckProtocol="HTTP", HealthCheckPath="/health",
        HealthCheckPort="traffic-port", HealthCheckIntervalSeconds=_HC_INTERVAL_S,
        HealthCheckTimeoutSeconds=_HC_TIMEOUT_S, HealthyThresholdCount=_HC_THRESHOLD,
        UnhealthyThresholdCount=_HC_THRESHOLD, Matcher={"HttpCode": "200"},
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elb.delete_target_group(TargetGroupArn=arn)))
    assert tg["HealthCheckPath"] == "/health", (
        f"the target group was created with HealthCheckPath {tg['HealthCheckPath']!r}; the guest "
        f"serves its verdict at /health and nothing else"
    )
    assert tg["Matcher"]["HttpCode"] == "200", (
        f"the target group matcher is {tg['Matcher']!r}; this check needs 200 ALONE to be healthy, "
        f"so that the guest's 503 is a failing health check rather than an accepted one"
    )
    return arn


def _target_health(elb, tg_arn, target):
    """The health of one target, located by (Id, Port) since both targets share the instance."""
    for description in elb.describe_target_health(
            TargetGroupArn=tg_arn)["TargetHealthDescriptions"]:
        if (description["Target"]["Id"] == target["Id"]
                and int(description["Target"]["Port"]) == int(target["Port"])):
            return description["TargetHealth"]
    return None


def _wait_target(elb, tg_arn, target, state, timeout_s=420):
    return _poll(
        lambda: _target_health(elb, tg_arn, target),
        lambda h: h is not None and h.get("State") == state,
        timeout_s=timeout_s, interval_s=5.0,
        what=f"target {target['Id']}:{target['Port']} reaching health state {state!r}")


@tags(
    "dp:endpoint",
    "plane:data",
    "concern:data-plane",
    "axis:negative-delivery",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A target whose /health answer stalls past the timeout goes unhealthy with Target.Timeout and
    gets no /app while probes still arrive and the sibling serves; ending the stall restores it.
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    scenario = ctx.unique_name("sim2real-dtgth-")
    token = ctx.unique_name("t-")

    azs = _usable_azs(ec2, 2)
    vpc, subnets = _public_vpc(ctx, ec2, azs, scenario)
    sg = _shared_sg(ctx, ec2, vpc, scenario)
    profile = _instance_profile(ctx, iam, scenario)
    instance_id = _launch(ctx, ec2, ssm, subnets[0], sg, profile, scenario)

    # The load balancer is created before the instance is waited on, so its several minutes of
    # provisioning overlap the guest's boot instead of following it.
    dns, lb_arn = _create_alb(ctx, elb, subnets, sg, scenario)
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # 1. Both servers come up answering /health promptly, which the guest confirms over loopback.
    deployed = _labels(_run_guest(ssm, instance_id, _deploy_script(), "deploying guest servers"))
    assert deployed.get("UNIT-A") == "active" and deployed.get("UNIT-B") == "active", (
        f"the guest servers did not come up: {deployed!r}; both systemd units must be 'active' "
        f"before any load-balancer observation can be attributed to the guest"
    )
    assert deployed.get("LOCAL-A") == "200" and deployed.get("LOCAL-B") == "200", (
        f"the guest's own loopback /health returned {deployed!r}, expected 200 from both servers"
    )

    tg_arn = _create_target_group(ctx, elb, vpc, scenario)
    target_a = {"Id": instance_id, "Port": _PORT_A}
    target_b = {"Id": instance_id, "Port": _PORT_B}
    for target in (target_a, target_b):
        _call_with_retry(lambda t=target: elb.register_targets(TargetGroupArn=tg_arn, Targets=[t]))
        ctx.on_cleanup(lambda t=target: _retry_delete(
            lambda: elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[t])))
    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elb.delete_listener(ListenerArn=listener_arn)))

    # 2. Baseline: both targets healthy, both serving real HTTP, both being probed. The counters are
    #    read from the guest's own logs, so they are the guest's account of what reached it.
    _wait_target(elb, tg_arn, target_a, "healthy")
    _wait_target(elb, tg_arn, target_b, "healthy")
    healthy_out = _run_guest(ssm, instance_id, _burst_script(dns, token, rounds=2),
                             "traffic with both targets healthy")
    healthy = _labels(healthy_out)
    served = set(_hits(healthy_out))
    assert served == {"BODY-A", "BODY-B"}, (
        f"with both targets healthy the load balancer served {sorted(served)!r} to a client inside "
        f"the guest across {len(_hits(healthy_out))} requests, expected both BODY-A and BODY-B"
    )
    app_a, app_b = int(healthy["APP-A"]), int(healthy["APP-B"])
    assert app_a > 0 and app_b > 0, (
        f"the guest's own access logs recorded {app_a} forwarded requests on port {_PORT_A} and "
        f"{app_b} on port {_PORT_B}; both servers must have been handed real HTTP, and this is "
        f"read from inside the guest rather than from a load-balancer metric"
    )
    hc_b_healthy = int(healthy["HC-B"])
    assert hc_b_healthy > 0, (
        f"the guest logged {hc_b_healthy} health probes on port {_PORT_B}; the load balancer must "
        f"actually have probed the guest for its 'healthy' verdict to have come from there"
    )

    # 3. Break EXACTLY ONE thing, inside the guest: server B now sits on a /health request for
    #    longer than the load balancer's timeout. No AWS call is made here, the server keeps
    #    running, and /app stays fast. The loopback timings prove the guest did this to itself.
    stalled = _labels(_run_guest(
        ssm, instance_id,
        f"printf 'STALL\\n' > {_state_path(_NAME_B)}\n" + _probe_timing_lines(),
        "stalling server B's health response from inside the guest"))
    assert stalled.get("FAST-B") == "no", (
        f"server B still answered its own loopback /health within the load balancer's "
        f"{_HC_TIMEOUT_S}s timeout (FAST-B={stalled.get('FAST-B')!r}); the stall must be observable "
        f"inside the guest before AWS can be said to have reacted to it"
    )
    assert stalled.get("FAST-A") == "yes", (
        f"the in-guest write also slowed port {_PORT_A} (FAST-A={stalled.get('FAST-A')!r}); exactly "
        f"one thing must break or the withdrawal below is not attributable to it"
    )

    # 4. An abandoned probe is reported as Target.Timeout, not Target.ResponseCodeMismatch, and the
    #    sibling stays healthy.
    unhealthy_b = _wait_target(elb, tg_arn, target_b, "unhealthy")
    assert unhealthy_b.get("Reason") == "Target.Timeout", (
        f"the target whose guest stalls its health response reported Reason "
        f"{unhealthy_b.get('Reason')!r} (description {unhealthy_b.get('Description')!r}), expected "
        f"Target.Timeout — a probe abandoned in flight must not be reported as a response code"
    )
    assert unhealthy_b.get("Description") == "Request timed out", (
        f"the timed-out target's health Description is {unhealthy_b.get('Description')!r}, "
        f"expected 'Request timed out'"
    )
    assert unhealthy_b.get("Reason") != "Target.ResponseCodeMismatch", (
        f"a stalled probe was reported as {unhealthy_b.get('Reason')!r}, the same reason a guest "
        f"answering an unaccepted status code gets; the two failure modes must stay distinguishable"
    )
    health_a = _target_health(elb, tg_arn, target_a)
    assert health_a is not None and health_a.get("State") == "healthy", (
        f"the sibling target went {health_a!r} as well; it must stay healthy or the withdrawal "
        f"below cannot be attributed to health rather than to the load balancer or the network"
    )

    # 5. THE EFFECT IS ABSENT, and the guest is the witness: the stalled server receives no
    #    forwarded request while its sibling does, yet its ARRIVAL log shows the probes still
    #    landing. That pair is what separates 'withdrawn from routing' from 'unreachable' — the
    #    load balancer is still reaching this server and still refusing to route to it.
    withdrawn_out = _run_guest(ssm, instance_id, _burst_script(dns, token, rounds=2),
                               "traffic with one target timing out")
    withdrawn = _labels(withdrawn_out)
    only_a = set(_hits(withdrawn_out))
    assert only_a == {"BODY-A"}, (
        f"with server B timing out the load balancer served {sorted(only_a)!r} across "
        f"{len(_hits(withdrawn_out))} requests, expected BODY-A alone — a target that fails its "
        f"health check beside a healthy sibling must receive nothing"
    )
    assert int(withdrawn["APP-B"]) == app_b, (
        f"the timed-out server's own forwarded-request count moved from {app_b} to "
        f"{withdrawn['APP-B']}; it must not receive a single request while it is unhealthy, and "
        f"note /app was never stalled — it would have answered instantly had it been asked"
    )
    assert int(withdrawn["APP-A"]) > app_a, (
        f"the healthy sibling's forwarded-request count did not move ({app_a} -> "
        f"{withdrawn['APP-A']}); the positive control must still be serving, or the absence above "
        f"only says the burst never left the guest"
    )
    assert int(withdrawn["HC-B"]) > hc_b_healthy, (
        f"the stalled server logged no further health probes on arrival ({hc_b_healthy} -> "
        f"{withdrawn['HC-B']}); the probes must still be REACHING the guest, or this check cannot "
        f"tell a probe abandoned in flight from a target the load balancer can no longer reach"
    )

    # 6. Undo the one broken thing, again from inside the guest: the stall ends, the target returns
    #    to service and is handed real HTTP again. Without this leg the check cannot tell a correct
    #    withdrawal from a load balancer that simply stopped using the target.
    recovered = _labels(_run_guest(
        ssm, instance_id,
        f"printf 'OK\\n' > {_state_path(_NAME_B)}\n" + _probe_timing_lines(),
        "ending the stall from inside the guest"))
    assert recovered.get("FAST-B") == "yes", (
        f"server B still did not answer its own loopback /health within {_HC_TIMEOUT_S}s after the "
        f"stall was lifted (FAST-B={recovered.get('FAST-B')!r})"
    )
    _wait_target(elb, tg_arn, target_b, "healthy")
    back_out = _run_guest(ssm, instance_id, _burst_script(dns, token, rounds=2),
                          "traffic after the guest stopped stalling")
    back = _labels(back_out)
    assert set(_hits(back_out)) == {"BODY-A", "BODY-B"}, (
        f"after the stall was lifted the load balancer served "
        f"{sorted(set(_hits(back_out)))!r}, expected both bodies — so server B was reachable and "
        f"serving throughout, and was excluded by how slowly it answered alone"
    )
    assert int(back["APP-B"]) > int(withdrawn["APP-B"]), (
        f"the restored server's forwarded-request count did not move "
        f"({withdrawn['APP-B']} -> {back['APP-B']}); returning to 'healthy' must return it to "
        f"service, and that is counted inside the guest"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
