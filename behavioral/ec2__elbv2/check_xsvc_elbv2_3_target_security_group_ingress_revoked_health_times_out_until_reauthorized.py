"""xsvc-elbv2-3-target-security-group-ingress-revoked-health-times-out-until-reauthorized."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-elbv2-3-target-security-group-ingress-revoked-health-times-out-until-reauthorized"
GROUP = "cross-service"
SERVICES = ["ec2", "elbv2"]

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]

_CIDR = "10.185.0.0/16"
_AL2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

#: HTTP/1.0 on purpose: every request from the ALB is a NEW TCP connection, so a security-group
#: change is observed by the next health check rather than masked by a tracked keep-alive flow.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF'
import http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def do_GET(self):
        body = b"ok" if self.path == "/health" else b"BACKEND-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

S(("", 80), H).serve_forever()
PYEOF
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
"""


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


def _retrying_delete(what, fn, *, attempts=30, interval_s=8):
    """Teardown-only: retry through DependencyViolation (ALB ENIs release late). A delete that
    never converges raises, so it cannot vanish silently."""
    def _wrapped():
        last = None
        for _ in range(attempts):
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if (code.endswith("NotFound") or code.endswith(".NotFound")
                        or code in ("TargetGroupNotFound", "LoadBalancerNotFound")):
                    return
                last = exc
            time.sleep(interval_s)
        raise RuntimeError(f"{what}: {last!r}")

    return _wrapped


def _usable_azs(ctx, want="t3.micro", n=2):
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= n, (
        f"{ctx.region} has {len(usable)} available AZs offering {want!r} ({usable!r}); an ALB "
        f"with an instance target needs {n}")
    return usable[:n]


def _own_vpc(ctx, azs):
    """A VPC this check creates, with an IGW and one public subnet per AZ given."""
    ec2 = ctx.client("ec2")

    def _spec(kind):
        return [{"ResourceType": kind, "Tags": list(_TAGS)}]

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(_retrying_delete(f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_spec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_retrying_delete(
        f"igw {igw_id}", lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(_retrying_delete(
        f"igw attachment {igw_id}",
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_spec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_retrying_delete(
        f"route table {rtb_id}", lambda: ec2.delete_route_table(RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    base = _CIDR.split(".")
    subnets = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{base[0]}.{base[1]}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=_spec("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(_retrying_delete(f"subnet {sid}", lambda s=sid: ec2.delete_subnet(SubnetId=s)))
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_retrying_delete(
            f"rtb association {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a), attempts=3))
        subnets.append(sid)
    return vpc_id, subnets


def _security_group(ctx, vpc_id, name_prefix):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(name_prefix), Description="sim2real alb security-group check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_retrying_delete(
        f"security group {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    return sg_id


def _launch_backend(ctx, subnet_id, sg_id, want="t3.micro"):
    """One EC2 instance, tagged AT CREATION (the only cleanup handle), waited to terminated."""
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(Name=_AL2023)["Parameter"]["Value"]
    tagset = list(_TAGS) + [{"Key": "Name", "Value": ctx.unique_name("sim2real-xsvc-ec2-")}]
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1, UserData=_USER_DATA,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
                            "AssociatePublicIpAddress": False}],
        TagSpecifications=[{"ResourceType": "instance", "Tags": tagset},
                           {"ResourceType": "volume", "Tags": tagset}],
    )["Instances"][0]["InstanceId"]

    def _state():
        try:
            got = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return None
            raise
        return got[0]["Instances"][0] if got else None

    def _drop_instance():
        _retrying_delete(f"instance {iid}",
                         lambda: ec2.terminate_instances(InstanceIds=[iid]), attempts=5)()
        for _ in range(90):
            inst = _state()
            if inst is None or inst["State"]["Name"] == "terminated":
                return
            time.sleep(5)
        raise RuntimeError(f"instance {iid} not terminated after 450s")

    ctx.on_cleanup(_drop_instance)
    inst = _poll_until(_state, lambda i: i is not None and i["State"]["Name"] != "pending",
                       timeout_s=300, interval_s=5, description=f"instance {iid} leaving pending")
    assert inst["State"]["Name"] == "running", (
        f"instance {iid} is {inst['State']['Name']!r}, expected 'running'")
    return iid


def _create_load_balancer(ctx, subnets, sg_id):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-xsvc-lb-")[:32].rstrip("-")
    lb = _retry_throttled(lambda: elb.create_load_balancer(
        Name=name, Subnets=subnets, SecurityGroups=[sg_id], Scheme="internet-facing",
        Type="application", IpAddressType="ipv4", Tags=list(_TAGS)))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        _retrying_delete(f"load balancer {arn}",
                         lambda: elb.delete_load_balancer(LoadBalancerArn=arn), attempts=5)()
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError:
                return
            time.sleep(4)
        raise RuntimeError(f"load balancer {arn} still described after 360s")

    ctx.on_cleanup(_drop_lb)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning", timeout_s=600, interval_s=10,
        description=f"load balancer {name} leaving provisioning")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _http(ctx, url, *, timeout=30):
    try:
        _url, _route = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return None, f"<transport: {type(exc).__name__}: {exc}>"
# ===== end helpers =====


@tags(
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "axis:happy-path",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Revoking the instance SG rule that admits the ALB's group turns the healthy target unhealthy with
    Target.Timeout and client requests into 504, and re-authorizing the identical rule restores healthy
    and 200 with no re-registration."""
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")

    azs = _usable_azs(ctx)
    vpc_id, subnets = _own_vpc(ctx, azs)
    lb_sg = _security_group(ctx, vpc_id, "sim2real-xsvc-lbsg-")
    ec2.authorize_security_group_ingress(GroupId=lb_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    be_sg = _security_group(ctx, vpc_id, "sim2real-xsvc-besg-")
    from_alb = [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                 "UserIdGroupPairs": [{"GroupId": lb_sg}]}]
    rules = ec2.authorize_security_group_ingress(GroupId=be_sg, IpPermissions=from_alb)
    rule_ids = [r["SecurityGroupRuleId"] for r in rules["SecurityGroupRules"]]
    assert len(rule_ids) == 1, f"authorize returned {rules['SecurityGroupRules']!r}, expected 1 rule"

    iid = _launch_backend(ctx, subnets[0], be_sg)
    lb = _create_load_balancer(ctx, subnets, lb_sg)
    lb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]

    tg_arn = _retry_throttled(lambda: elb.create_target_group(
        Name=ctx.unique_name("sim2real-xsvc-tg-")[:32].rstrip("-"), Protocol="HTTP", Port=80,
        VpcId=vpc_id, TargetType="instance", HealthCheckProtocol="HTTP", HealthCheckPath="/health",
        HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2, HealthyThresholdCount=2,
        UnhealthyThresholdCount=2, Tags=list(_TAGS)))["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_retrying_delete(f"target group {tg_arn}",
                                    lambda: elb.delete_target_group(TargetGroupArn=tg_arn),
                                    attempts=15, interval_s=4))
    elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": iid, "Port": 80}])
    listener_arn = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}]))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_retrying_delete("listener", lambda: elb.delete_listener(ListenerArn=listener_arn),
                                    attempts=3))

    trail = []

    def _health():
        d = elb.describe_target_health(
            TargetGroupArn=tg_arn, Targets=[{"Id": iid, "Port": 80}])["TargetHealthDescriptions"]
        h = d[0]["TargetHealth"]
        trail.append((h.get("State"), h.get("Reason")))
        return h

    # ---- POSITIVE CONTROL: healthy, and serving through the ALB. --------------------------------
    _poll_until(_health, lambda h: h.get("State") == "healthy", timeout_s=600, interval_s=10,
                description=f"target {iid} healthy before the revoke (trail {trail[-6:]!r})")
    served = _poll_until(lambda: _http(ctx, f"http://{dns}/serve"), lambda r: r[0] == 200,
                         timeout_s=420, interval_s=10, description="the ALB serving the target")
    assert served == (200, "BACKEND-OK"), f"before the revoke the ALB returned {served!r}"

    # ---- BREAK ONE THING: revoke the target's ingress from the ALB's group. ---------------------
    revoked = ec2.revoke_security_group_ingress(GroupId=be_sg, SecurityGroupRuleIds=rule_ids)
    assert revoked.get("Return") is True and not revoked.get("UnknownIpPermissions"), (
        f"revoke returned {revoked!r}, expected Return=True and no unknown permissions")
    del trail[:]
    down = _poll_until(_health, lambda h: h.get("State") == "unhealthy", timeout_s=300,
                       interval_s=5, description=f"target {iid} unhealthy after the revoke "
                                                 f"(trail {trail[-6:]!r})")
    print(f"[health] after revoke: {down!r}; trail {trail!r}")
    assert down.get("Reason") == "Target.Timeout", (
        f"with its ingress from the ALB revoked the target is unhealthy with reason "
        f"{down.get('Reason')!r} ({down!r}), expected 'Target.Timeout' — a dropped SYN times out")
    assert all(r in (None, "Target.Timeout") for _, r in trail), (
        f"the target passed through a reason other than Target.Timeout on the way down: {trail!r}")

    # The only target is unhealthy, so the ALB fails open and tries it — and the connect times out.
    blocked = _http(ctx, f"http://{dns}/serve-while-revoked", timeout=60)
    assert blocked[0] == 504, (
        f"with the target's ingress revoked the ALB returned {blocked!r}, expected the load "
        f"balancer's own 504 (it cannot connect to the target)")
    assert "BACKEND-OK" not in blocked[1], f"the 504 body carried the target's bytes: {blocked!r}"

    # ---- RESTORE: re-authorize the identical rule; no re-registration. -------------------------
    ec2.authorize_security_group_ingress(GroupId=be_sg, IpPermissions=from_alb)
    del trail[:]
    up = _poll_until(_health, lambda h: h.get("State") == "healthy", timeout_s=300, interval_s=5,
                     description=f"target {iid} healthy again after re-authorizing "
                                 f"(trail {trail[-6:]!r})")
    assert "Reason" not in up, f"the restored healthy target carries a reason: {up!r}"
    again = _poll_until(lambda: _http(ctx, f"http://{dns}/serve-restored"), lambda r: r[0] == 200,
                        timeout_s=120, interval_s=5, description="the ALB serving after restore")
    assert again == (200, "BACKEND-OK"), f"after re-authorizing the ALB returned {again!r}"
    listed = elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert [(t["Target"]["Id"], t["Target"]["Port"]) for t in listed] == [(iid, 80)], (
        f"the target group lists {listed!r}, expected only the original registration {iid}:80")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
