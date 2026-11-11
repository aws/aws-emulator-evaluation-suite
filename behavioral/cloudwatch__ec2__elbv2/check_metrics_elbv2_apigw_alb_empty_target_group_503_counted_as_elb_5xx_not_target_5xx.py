"""metrics-elbv2-apigw-alb-empty-target-group-503-counted-as-elb-5xx-not-target-5xx."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-elbv2-apigw-alb-empty-target-group-503-counted-as-elb-5xx-not-target-5xx"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch", "ec2", "elbv2"]

_N_OK = 6
_N_ERR = 5
_N_503 = 8

# ===== helpers (self-contained) =====
_TAG_KEY = "sim2real"
_NS = "AWS/ApplicationELB"

#: The target: a stdlib HTTP server started from user-data. It answers
#:   /health            200 (or 500 once /flip-unhealthy was requested)
#:   .../err            500 "TARGET-500:<marker>"
#:   .../bytes/<n>      200 with an n-byte body
#:   anything else      200 "TARGET-200:<marker>"
_SERVER = r'''
import http.server, socketserver
MARKER = "__MARKER__"
STATE = {"healthy": True}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?", 1)[0]
        if p == "/health":
            if STATE["healthy"]:
                return self._send(200, b"ok")
            return self._send(500, b"unhealthy")
        if p.endswith("/flip-unhealthy"):
            STATE["healthy"] = False
            return self._send(200, ("FLIPPED:" + MARKER).encode())
        if p.endswith("/err"):
            return self._send(500, ("TARGET-500:" + MARKER).encode())
        if "/bytes/" in p:
            return self._send(200, b"x" * int(p.rsplit("/", 1)[1]))
        return self._send(200, ("TARGET-200:" + MARKER).encode())
    def log_message(self, *a):
        pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("", 80), H).serve_forever()
'''


def _user_data(marker):
    return ("#!/bin/bash\ncat > /opt/sim2real_srv.py <<'PYEOF'\n"
            + _SERVER.replace("__MARKER__", marker)
            + "\nPYEOF\nnohup python3 /opt/sim2real_srv.py >/dev/null 2>&1 &\n")


def _tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": _TAG_KEY, "Value": CHECK}]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout, quoting the last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


#: Teardown error codes that mean the resource is already gone; every other failure is raised.
_GONE = frozenset({
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidSubnetID.NotFound", "InvalidAssociationID.NotFound", "ListenerNotFound", "RuleNotFound"})


def _quiet(fn):
    """Teardown: tolerate only an already-gone resource; raise every other failure."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _GONE:
                raise
    return _wrapped


def _http(ctx, url, headers=None, timeout=30):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**(headers or {}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _usable_azs(ec2, instance_type, need):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= need, (
        f"need {need} available AZs offering {instance_type!r}, found {usable!r} "
        f"(offerings {sorted(offered)!r})")
    return usable[:need]


def _al2023_ami(ec2):
    images = ec2.describe_images(Owners=["amazon"], Filters=[
        {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-*-x86_64"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "state", "Values": ["available"]},
    ])["Images"]
    assert images, "describe_images found no Amazon-owned al2023 x86_64 AMI in this region"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _network(ctx, azs, cidr_second_octet):
    """Own VPC + IGW + one public subnet per AZ. Never the default VPC."""
    ec2 = ctx.client("ec2")
    base = f"10.{cidr_second_octet}"
    vpc = ec2.create_vpc(CidrBlock=f"{base}.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags(ctx.unique_name("sim2real-vpc-"))}])["Vpc"]["VpcId"]
    def _drop_vpc():
        for _ in range(10):
            try:
                _delete_net(ec2, "delete_vpc", VpcId=vpc)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                    return
                time.sleep(6)
        raise RuntimeError(f"vpc {vpc} could not be deleted")

    ctx.on_cleanup(_drop_vpc)
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags(ctx.unique_name("sim2real-igw-"))}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_quiet(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(_quiet(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw, VpcId=vpc)))
    rtb = ec2.create_route_table(VpcId=vpc, TagSpecifications=[
        {"ResourceType": "route-table", "Tags": _tags(ctx.unique_name("sim2real-rtb-"))}]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_quiet(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnets = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(VpcId=vpc, CidrBlock=f"{base}.{i}.0/24", AvailabilityZone=az,
                                TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(
                                    ctx.unique_name("sim2real-sn-"))}])["Subnet"]["SubnetId"]
        ctx.on_cleanup(_quiet(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_quiet(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
        subnets.append(sid)
    return vpc, subnets


def _security_group(ctx, vpc, desc, ingress):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-sg-")
    sg = ec2.create_security_group(GroupName=name, Description=desc, VpcId=vpc, TagSpecifications=[
        {"ResourceType": "security-group", "Tags": _tags(name)}])["GroupId"]

    def _drop():
        # ENIs of the load balancer and instances release this group asynchronously.
        for _ in range(40):
            try:
                _delete_net(ec2, "delete_security_group", GroupId=sg)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidGroup.NotFound":
                    return
                time.sleep(6)
        raise RuntimeError(f"security group {sg} could not be deleted")

    ctx.on_cleanup(_drop)
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[ingress(sg)])
    return sg


def _instance(ctx, ami, subnet, sg, marker):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-tgt-")
    iid = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet,
        SecurityGroupIds=[sg], UserData=_user_data(marker),
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags(name)},
                           {"ResourceType": "volume", "Tags": _tags(name)}],
    )["Instances"][0]["InstanceId"]

    def _drop():
        try:
            ec2.terminate_instances(InstanceIds=[iid])
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=[iid], WaiterConfig={"Delay": 2, "MaxAttempts": 200})
        except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
            teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if teardown_code not in ("InvalidInstanceID.NotFound",):
                raise RuntimeError(
                    f"instance {iid} termination not confirmed: {exc}"
                ) from exc

    ctx.on_cleanup(_drop)
    return iid


def _load_balancer(ctx, subnets, sg):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-mlb-")
    lb = elb.create_load_balancer(Name=name, Subnets=subnets, SecurityGroups=[sg],
                                  Scheme="internet-facing", Type="application",
                                  Tags=_tags(name))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)
        raise RuntimeError(f"load balancer {arn} still described after delete")

    ctx.on_cleanup(_drop)
    return name, lb


def _target_group(ctx, vpc):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-mtg-")
    tg = elb.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/health", HealthCheckIntervalSeconds=5,
        HealthCheckTimeoutSeconds=2, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        Matcher={"HttpCode": "200"}, Tags=_tags(name))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop():
        for _ in range(15):
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "TargetGroupNotFound":
                    return
                time.sleep(4)
        raise RuntimeError(f"target group {arn} could not be deleted")

    ctx.on_cleanup(_drop)
    # Short drain so teardown is not held up by the 300 s default.
    elb.modify_target_group_attributes(TargetGroupArn=arn, Attributes=[
        {"Key": "deregistration_delay.timeout_seconds", "Value": "5"}])
    return name, arn


def _listener(ctx, lb_arn):
    elb = ctx.client("elbv2")
    arn = elb.create_listener(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[
        {"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "404", "ContentType": "text/plain", "MessageBody": "ALB-DEFAULT"}}]
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_quiet(lambda: elb.delete_listener(ListenerArn=arn)))
    return arn


def _header_rule(ctx, listener_arn, priority, header, value, tg_arn, path=None):
    """Forward only requests carrying a header value this run minted. An internet-facing load
    balancer is scanned by strangers within minutes; they cannot guess the value, so they fall
    through to the fixed-response default, which chooses no target and is excluded from every
    target-scoped metric this check compares exactly."""
    elb = ctx.client("elbv2")
    conds = [{"Field": "http-header", "HttpHeaderConfig": {
        "HttpHeaderName": header, "Values": [value]}}]
    if path:
        conds.append({"Field": "path-pattern", "PathPatternConfig": {"Values": [path]}})
    arn = elb.create_rule(ListenerArn=listener_arn, Priority=priority, Conditions=conds,
                          Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}])["Rules"][0]["RuleArn"]
    ctx.on_cleanup(_quiet(lambda: elb.delete_rule(RuleArn=arn)))
    return arn


def _wait_lb_active(ctx, arn):
    elb = ctx.client("elbv2")
    lb = _poll_until(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
                     lambda x: x["State"]["Code"] in ("active", "failed"), timeout_s=600,
                     interval_s=10, description="load balancer leaving 'provisioning'")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _target_states(ctx, tg_arn):
    elb = ctx.client("elbv2")
    return {d["Target"]["Id"]: (d["TargetHealth"]["State"], d["TargetHealth"].get("Reason"))
            for d in elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]}


def _wait_healthy(ctx, tg_arn, ids):
    return _poll_until(lambda: _target_states(ctx, tg_arn),
                       lambda s: all(s.get(i, ("",))[0] == "healthy" for i in ids),
                       timeout_s=720, interval_s=10,
                       description=f"targets {ids!r} reaching 'healthy' in {tg_arn}")


def _dims(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _stat(ctx, metric, dims, start, statistic):
    """Total of one statistic over every 60 s datapoint from `start` to now+3 min."""
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=_NS, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=[statistic])["Datapoints"]
    return sum(p[statistic] for p in pts), len(pts)


def _align_minute(margin_s=3, guard_s=20):
    """Block until `margin_s` into a fresh UTC minute that begins at least `guard_s` after now,
    and return that minute. Every warm-up request lands in an EARLIER 60 s bucket than the
    measured batch, so a window starting here holds only the batch. The guard is measured: on
    execute-api, requests sent ~3 s before a boundary were counted in the next minute on a
    clock-synced host. A computed alignment with a deadline, not a fixed sleep."""
    start = (datetime.now(timezone.utc) + timedelta(seconds=guard_s)).replace(
        second=0, microsecond=0)
    deadline = time.monotonic() + 130
    while time.monotonic() < deadline:
        now = datetime.now(timezone.utc)
        minute = now.replace(second=0, microsecond=0)
        if minute > start and now.second >= margin_s:
            return minute
        time.sleep(1)
    raise AssertionError("the UTC clock did not advance a minute within 130 s")
# ===== end helpers =====



def _body(ctx) -> None:
    """A request routed to a target group with NO registered targets is refused by the load
    balancer itself — HTTP 503 "503 Service Temporarily Unavailable" from ``awselb/2.0`` — and is
    counted in HTTPCode_ELB_503_Count / HTTPCode_ELB_5XX_Count, never in
    HTTPCode_Target_5XX_Count, while a 500 the TARGET returns is counted the other way round.

    No API response shows it: the refusal happens on the load balancer's data plane (no ELBv2 API is
    called), and the claim is about which CloudWatch series the refusal is attributed to. An
    implementation that files every 5xx it proxies under one counter — the natural shortcut —
    returns the same control-plane responses as a faithful one.

    Break exactly one thing: the empty target group has no targets. Positive control in the same
    batch: a live target group whose target returns 500 on /err must land in
    HTTPCode_Target_5XX_Count, so "target 5xx stayed at the target's count" cannot be a pipeline
    that never publishes it. Then the one broken thing is repaired (the target is registered in
    the empty group) and the same route serves 200, proving the route was right all along.
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")

    azs = _usable_azs(ec2, "t3.micro", 2)
    ami = _al2023_ami(ec2)
    vpc, subnets = _network(ctx, azs, 63)
    alb_sg = _security_group(ctx, vpc, "sim2real alb ingress", lambda sg: {
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    tgt_sg = _security_group(ctx, vpc, "sim2real target ingress from alb", lambda sg: {
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "UserIdGroupPairs": [{"GroupId": alb_sg}]})

    iid = _instance(ctx, ami, subnets[0], tgt_sg, "A")
    lb_name, lb = _load_balancer(ctx, subnets, alb_sg)
    lb_arn = lb["LoadBalancerArn"]
    live_name, live_arn = _target_group(ctx, vpc)
    empty_name, empty_arn = _target_group(ctx, vpc)
    listener = _listener(ctx, lb_arn)
    token = ctx.unique_name("t")
    _header_rule(ctx, listener, 5, "X-Sim2real-Run", token, empty_arn, path="/empty/*")
    _header_rule(ctx, listener, 10, "X-Sim2real-Run", token, live_arn)

    ec2.get_waiter("instance_running").wait(InstanceIds=[iid],
                                            WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    elb.register_targets(TargetGroupArn=live_arn, Targets=[{"Id": iid}])
    _wait_lb_active(ctx, lb_arn)
    _wait_healthy(ctx, live_arn, [iid])

    lb_dim = f"app/{lb_name}/{lb_arn.rsplit('/', 1)[-1]}"
    empty_dim = f"targetgroup/{empty_name}/{empty_arn.rsplit('/', 1)[-1]}"
    lbd = _dims(LoadBalancer=lb_dim)
    emptyd = _dims(LoadBalancer=lb_dim, TargetGroup=empty_dim)
    base = f"http://{lb['DNSName']}"
    hdr = {"X-Sim2real-Run": token}

    _poll_until(lambda: _http(ctx, f"{base}/warm/ok", hdr)[0], lambda s: s == 200, timeout_s=180,
                interval_s=3, description="the live rule forwarding to the healthy target")
    _poll_until(lambda: _http(ctx, f"{base}/empty/warm", hdr)[0], lambda s: s == 503, timeout_s=180,
                interval_s=3, description="the empty-group rule answering 503")

    t0 = _align_minute()
    for i in range(_N_OK):
        status, _h, body = _http(ctx, f"{base}/m/ok", hdr)
        assert (status, body) == (200, b"TARGET-200:A"), f"ok {i}: {status} {body[:60]!r}"
    for i in range(_N_ERR):
        status, _h, body = _http(ctx, f"{base}/m/err", hdr)
        assert (status, body) == (500, b"TARGET-500:A"), f"err {i}: {status} {body[:60]!r}"
    for i in range(_N_503):
        status, headers, body = _http(ctx, f"{base}/empty/m", hdr)
        server = {k.lower(): v for k, v in headers.items()}.get("server")
        assert status == 503 and b"503 Service Temporarily Unavailable" in body, (
            f"empty-group request {i} returned {status} {body[:120]!r}, expected the load "
            f"balancer's own '503 Service Temporarily Unavailable'")
        assert server == "awselb/2.0", (
            f"the 503 must be generated by the load balancer (Server: awselb/2.0), got {server!r}")

    # Positive control first: target-generated 500s land in the TARGET series.
    t5, _ = _poll_until(lambda: _stat(ctx, "HTTPCode_Target_5XX_Count", lbd, t0, "Sum"),
                        lambda r: r[0] >= _N_ERR, timeout_s=600, interval_s=15,
                        description=f"HTTPCode_Target_5XX_Count reaching {_N_ERR}")
    e503, _ = _poll_until(lambda: _stat(ctx, "HTTPCode_ELB_503_Count", lbd, t0, "Sum"),
                          lambda r: r[0] >= _N_503, timeout_s=300, interval_s=15,
                          description=f"HTTPCode_ELB_503_Count reaching {_N_503}")
    e5, _ = _poll_until(lambda: _stat(ctx, "HTTPCode_ELB_5XX_Count", lbd, t0, "Sum"),
                        lambda r: r[0] >= _N_503, timeout_s=300, interval_s=15,
                        description=f"HTTPCode_ELB_5XX_Count reaching {_N_503}")
    rc, _ = _poll_until(lambda: _stat(ctx, "RequestCount", lbd, t0, "Sum"),
                        lambda r: r[0] >= _N_OK + _N_ERR, timeout_s=300, interval_s=15,
                        description="RequestCount reaching the target-served requests")
    assert t5 == _N_ERR, (
        f"HTTPCode_Target_5XX_Count = {t5}, expected exactly the {_N_ERR} target-returned 500s; "
        f"the {_N_503} load-balancer 503s must not be attributed to a target")
    assert (e503, e5) == (_N_503, _N_503), (
        f"ELB 503/5XX counts were {e503}/{e5}, expected exactly {_N_503}/{_N_503}; the target's "
        f"{_N_ERR} 500s must not be attributed to the load balancer")
    assert rc == _N_OK + _N_ERR, (
        f"RequestCount = {rc}, expected {_N_OK + _N_ERR}: the {_N_503} requests to the empty group "
        f"chose no target")
    t5_empty, n_pts = _stat(ctx, "HTTPCode_Target_5XX_Count", emptyd, t0, "Sum")
    assert (t5_empty, n_pts) == (0, 0), (
        f"the empty target group has no target, so no target 5xx series may exist for it; got "
        f"sum {t5_empty} over {n_pts} datapoints")

    # Repair the one broken thing; the same route must now reach the target.
    elb.register_targets(TargetGroupArn=empty_arn, Targets=[{"Id": iid}])
    _wait_healthy(ctx, empty_arn, [iid])
    status, _h, body = _poll_until(lambda: _http(ctx, f"{base}/empty/r", hdr),
                                   lambda r: r[0] == 200, timeout_s=180, interval_s=3,
                                   description="the repaired group serving the route")
    assert body == b"TARGET-200:A", f"repaired route served {body[:60]!r}, expected TARGET-200:A"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """Runs the claims in `_body`, then this check's teardowns inside its own budget: an ALB's
    ENIs outlive DeleteLoadBalancer, so the VPC teardown needs longer than the default cleanup window."""
    try:
        _body(ctx)
    finally:
        ctx.run_cleanups()


# A load balancer or instance in this VPC releases its ENIs after its delete returns, so each network
# delete waits for the ENIs to go and retries DependencyViolation inside one window shared by all of
# this check's network deletes, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
