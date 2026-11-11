"""elbv2attr-deep-elbv2-1-unhealthy-state-routing-min-healthy-count-serves-unhealthy-target."""
from __future__ import annotations

import http.client
import urllib.parse
import socket
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elbv2attr-deep-elbv2-1-unhealthy-state-routing-min-healthy-count-serves-unhealthy-target"
GROUP = "data-plane"
SERVICES = ["elbv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_CIDR = "10.183.0.0/16"

_TRANSPORT_ERRORS = (OSError, http.client.HTTPException, socket.timeout)


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_until_gone(fn, gone_codes, *, timeout_s=600, interval_s=10):
    """Teardown that converges: retry a delete through DependencyViolation / ResourceInUse (a
    deleted load balancer releases its ENIs, and its listener releases its certificate, minutes
    after the delete returns) until it succeeds or the resource is reported gone. Raises on
    timeout so a leak is loud rather than swallowed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone_codes:
                return
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _own_public_vpc(ctx, cidr=_CIDR, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: ec2.delete_vpc(VpcId=vpc_id), {"InvalidVpcID.NotFound"}))

    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
    )
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets} for a load balancer"
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _delete_until_gone(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            {"Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"})
        _delete_until_gone(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
            {"InvalidInternetGatewayID.NotFound"})

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: ec2.delete_route_table(RouteTableId=rtb_id), {"InvalidRouteTableID.NotFound"}))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sid: _delete_until_gone(
            lambda: ec2.delete_subnet(SubnetId=s), {"InvalidSubnetID.NotFound"}))
        subnet_ids.append(sid)
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc: _delete_until_gone(
            lambda: ec2.disassociate_route_table(AssociationId=a),
            {"InvalidAssociationID.NotFound"}))
    return vpc_id, subnet_ids


def _ingress_sg(ctx, vpc_id, ports, source):
    """A security group admitting tcp *ports* from *source* (IpRanges or UserIdGroupPairs)."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: ec2.delete_security_group(GroupId=sg_id), {"InvalidGroup.NotFound"}))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             **source}
            for p in ports
        ],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, sg_id):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(ctx.unique_name("sim2real-behav-lb-"))
    lb = _retry_throttled(lambda: elb.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application",
        Scheme="internet-facing", Tags=list(_TAGS),
    ))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        _delete_until_gone(lambda: elb.delete_load_balancer(LoadBalancerArn=arn),
                           {"LoadBalancerNotFound"})
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning",
        timeout_s=timeout_s, interval_s=10,
        description="load balancer leaving the provisioning state",
    )
    assert lb["State"]["Code"] == "active", (
        f"load balancer state {lb['State']!r}, expected State.Code == 'active'"
    )
    return lb


def _usable_azs(ctx, want):
    """AZs that are available AND offer `want` — both halves are load-bearing: offerings do not
    report zone state, and zone listings say nothing about instance types."""
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= 2, f"need 2 available AZs offering {want!r}, got {usable!r}"
    return usable


def _describe_instance(ec2, iid):
    """DescribeInstances tolerating the eventual consistency right after RunInstances."""
    last = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            return ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise
            last = exc
        except (IndexError, KeyError) as exc:
            last = exc
        time.sleep(2)
    raise AssertionError(f"instance {iid} never appeared in DescribeInstances: {last!r}")


def _instance_terminated(ec2, iid) -> bool:
    """Whether the instance is terminated; an instance AWS no longer lists counts as terminated."""
    try:
        found = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return True
        raise
    return not found or found[0]["Instances"][0]["State"]["Name"] == "terminated"


def _launch_backend(ctx, subnet_id, sg_id, user_data, want):
    """One EC2 instance running the HTTP backends from user-data, tagged AT CREATION (an
    untagged instance is invisible to tag cleanup). The AMI comes from the public SSM parameter,
    never a hardcoded id."""
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-behav-ec2-")
    tags = list(_TAGS) + [{"Key": "Name", "Value": name}]
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], UserData=user_data,
        InstanceInitiatedShutdownBehavior="terminate",
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags},
                           {"ResourceType": "volume", "Tags": tags}],
    )["Instances"][0]["InstanceId"]

    def _drop_instance():
        _delete_until_gone(lambda: ec2.terminate_instances(InstanceIds=[iid]),
                           {"InvalidInstanceID.NotFound"}, timeout_s=120)
        # Wait for 'terminated': the instance ENI holds the security group the next cleanup drops.
        deadline = time.monotonic() + 360.0
        while not _instance_terminated(ec2, iid):
            if time.monotonic() >= deadline:
                raise AssertionError(f"instance {iid} not terminated after 360 s of teardown")
            time.sleep(5)

    ctx.on_cleanup(_drop_instance)
    state = _poll_until(
        lambda: _describe_instance(ec2, iid)["State"]["Name"],
        lambda s: s != "pending", timeout_s=300, interval_s=5,
        description=f"instance {iid} leaving the pending state",
    )
    assert state == "running", f"instance {iid} state {state!r}, expected running"
    return iid


def _target_states(ctx, tg_arn):
    elb = ctx.client("elbv2")
    return {
        (d["Target"]["Id"], d["Target"]["Port"]): (d["TargetHealth"]["State"],
                                                    d["TargetHealth"].get("Reason"))
        for d in elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    }


def _get(ctx, host, path, timeout=10):
    _url, _route = ctx.endpoint_route(f"http://{host}")
    _t = urllib.parse.urlsplit(_url)
    conn = http.client.HTTPConnection(_t.hostname, _t.port or 80, timeout=timeout)
    try:
        conn.request("GET", path, headers={**({"Host": host, "Connection": "close"}), **_route})
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace").strip()
    finally:
        conn.close()


def _sample(ctx, host, path, n):
    """n fresh-connection requests; returns the list of (status, body). Transport errors are
    recorded as values so a poll can retry through them."""
    out = []
    for _ in range(n):
        try:
            out.append(_get(ctx, host, path))
        except _TRANSPORT_ERRORS as exc:
            out.append((None, f"<{type(exc).__name__}>"))
    return out


def _set_min_healthy(ctx, tg_arn, count):
    elb = ctx.client("elbv2")
    key = "target_group_health.unhealthy_state_routing.minimum_healthy_targets.count"
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=[{"Key": key, "Value": str(count)}]))
    got = {a["Key"]: a["Value"] for a in elb.describe_target_group_attributes(
        TargetGroupArn=tg_arn)["Attributes"]}.get(key)
    assert got == str(count), f"DescribeTargetGroupAttributes reports {key}={got!r} after setting {count}"


_KEY = "target_group_health.unhealthy_state_routing.minimum_healthy_targets.count"

#: One instance, two backends. Port 80 is TARGET-A and passes the /hc health check; port 8080 is
#: TARGET-B and answers /hc with 404 — so B is UNHEALTHY yet fully able to serve "/". Exactly
#: one thing differs between the legs below: the target group's minimum_healthy_targets.count.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver
import threading


def make(label, hc_code):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path.split("?")[0] == "/hc":
                code, body = hc_code, b"HC"
            else:
                code, body = 200, label.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


b = S(("", 8080), make("TARGET-B", 404))
threading.Thread(target=b.serve_forever, daemon=True).start()
S(("", 80), make("TARGET-A", 200)).serve_forever()
PYEOF_INNER
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
"""

_N = 24


_DNS_KEY = "target_group_health.dns_failover.minimum_healthy_targets.count"


def _bodies(ctx, host, n=_N):
    return [b for _st, b in _sample(ctx, host, "/", n)]


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """With 1 of 2 targets healthy, unhealthy-state-routing minimum_healthy_targets.count=1 serves only the healthy
    target, while count=2 fails open and the still-unhealthy target serves too, with target health unchanged."""
    elb = ctx.client("elbv2")
    want = "t3.micro"
    usable = _usable_azs(ctx, want)
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    # The load balancer admits the caller; the backend admits only the load balancer's group.
    sg_id = _ingress_sg(ctx, vpc_id, (80,), {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _ingress_sg(ctx, vpc_id, (80, 8080), {"UserIdGroupPairs": [{"GroupId": sg_id}]})
    sub_az = {s["SubnetId"]: s["AvailabilityZone"] for s in ctx.client("ec2").describe_subnets(
        SubnetIds=subnet_ids)["Subnets"]}
    inst_subnet = next((s for s in subnet_ids if sub_az[s] in usable), None)
    assert inst_subnet, f"none of {sub_az!r} is in an AZ offering {want}: {usable!r}"
    iid = _launch_backend(ctx, inst_subnet, be_sg, _USER_DATA, want)

    lb = _create_load_balancer(ctx, subnet_ids, sg_id)
    tg_arn = _retry_throttled(lambda: elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-behav-tg-")), Protocol="HTTP", Port=80,
        VpcId=vpc_id, TargetType="instance", HealthCheckProtocol="HTTP", HealthCheckPath="/hc",
        HealthCheckPort="traffic-port", HealthCheckIntervalSeconds=5,
        HealthCheckTimeoutSeconds=2, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        Matcher={"HttpCode": "200"}, Tags=list(_TAGS)))["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_target_group(TargetGroupArn=tg_arn), {"TargetGroupNotFound"},
        timeout_s=180))
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=[{"Key": _DNS_KEY, "Value": "off"}]))
    targets = [{"Id": iid, "Port": 80}, {"Id": iid, "Port": 8080}]
    elb.register_targets(TargetGroupArn=tg_arn, Targets=targets)
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.deregister_targets(TargetGroupArn=tg_arn, Targets=targets),
        {"TargetGroupNotFound", "InvalidTarget"}, timeout_s=60))
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    listener_arn = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    ))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_listener(ListenerArn=listener_arn), {"ListenerNotFound"}))

    a, b = (iid, 80), (iid, 8080)
    split = {a: ("healthy", None), b: ("unhealthy", "Target.ResponseCodeMismatch")}
    states = _poll_until(lambda: _target_states(ctx, tg_arn), lambda st: st == split,
                         timeout_s=480, interval_s=5,
                         description="TARGET-A healthy and TARGET-B unhealthy on /hc")
    assert states == split, f"target health {states!r}, expected {split!r}"
    attrs = {x["Key"]: x["Value"] for x in elb.describe_target_group_attributes(
        TargetGroupArn=tg_arn)["Attributes"]}
    assert attrs.get(_KEY) == "1", f"default {_KEY} is {attrs.get(_KEY)!r}, expected '1'"
    host = lb["DNSName"]

    # Leg 1 — count=1 (default), the positive control: 1 healthy >= 1, normal routing, so the
    # unhealthy target receives nothing.
    leg1 = _poll_until(lambda: _bodies(ctx, host), lambda bs: set(bs) == {"TARGET-A"},
                       timeout_s=300, interval_s=5,
                       description="count=1: only the healthy TARGET-A being served")
    assert set(leg1) == {"TARGET-A"}, f"count=1 served {sorted(set(leg1))!r}, expected only TARGET-A"

    # Leg 2 — change exactly one thing: count=2 > 1 healthy, so the group is in its unhealthy
    # state and routing fails open to ALL targets, the unhealthy one included.
    _set_min_healthy(ctx, tg_arn, 2)
    leg2 = _poll_until(lambda: _bodies(ctx, host), lambda bs: "TARGET-B" in bs,
                       timeout_s=300, interval_s=5,
                       description="count=2: the unhealthy TARGET-B starting to be served")
    assert set(leg2) == {"TARGET-A", "TARGET-B"}, (
        f"count=2 with 1 of 2 healthy served {sorted(set(leg2))!r}; expected BOTH targets "
        f"(fail open to all targets in the unhealthy state)"
    )
    held = _bodies(ctx, host)
    assert set(held) == {"TARGET-A", "TARGET-B"}, (
        f"a second sample at count=2 served {sorted(set(held))!r}; fail-open must persist"
    )
    during = _target_states(ctx, tg_arn)
    assert during == split, (
        f"target health moved during the count=2 leg ({during!r}); TARGET-B must still be "
        f"UNHEALTHY while it is being served, or the leg proves nothing about the attribute"
    )

    # Leg 3 — restore count=1: the unhealthy target is withdrawn again.
    _set_min_healthy(ctx, tg_arn, 1)
    leg3 = _poll_until(lambda: _bodies(ctx, host), lambda bs: set(bs) == {"TARGET-A"},
                       timeout_s=300, interval_s=5,
                       description="count restored to 1: TARGET-B withdrawn again")
    assert set(leg3) == {"TARGET-A"}, f"after restore served {sorted(set(leg3))!r}, expected TARGET-A"
    assert _target_states(ctx, tg_arn) == split, "target health moved during the restore leg"

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
