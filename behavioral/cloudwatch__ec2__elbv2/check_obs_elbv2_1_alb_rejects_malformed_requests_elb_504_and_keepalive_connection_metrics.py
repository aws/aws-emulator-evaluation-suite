"""obs-elbv2-1-alb-rejects-malformed-requests-elb-504-and-keepalive-connection-metrics."""
from __future__ import annotations

import http.client
import urllib.parse
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-elbv2-1-alb-rejects-malformed-requests-elb-504-and-keepalive-connection-metrics"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch", "ec2", "elbv2"]

_N_BAD = 5        # N1: raw-socket requests whose request line is not HTTP
_N_SLOW = 4       # N2: well-formed requests to a path that sleeps past the idle timeout
_N_KEEP = 25      # N3: well-formed requests on ONE keep-alive connection
_IDLE_S = 1       # idle_timeout.timeout_seconds on the load balancer
_SLEEP_S = 4      # how long the target sleeps before answering /slow

# ===== helpers (self-contained) =====
_TAG_KEY = "sim2real"
_NS = "AWS/ApplicationELB"

#: The target: a stdlib HTTP server started from user-data. It answers
#:   /health        200
#:   .../slow       200 after sleeping _SLEEP_S (the load balancer gives up first)
#:   anything else  200 "TARGET-200:<marker>"
_SERVER = r'''
import http.server, socketserver, time
MARKER = "__MARKER__"
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
            return self._send(200, b"ok")
        if p.endswith("/slow"):
            time.sleep(__SLEEP__)
            return self._send(200, ("TARGET-SLOW:" + MARKER).encode())
        return self._send(200, ("TARGET-200:" + MARKER).encode())
    def log_message(self, *a):
        pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("", 80), H).serve_forever()
'''


def _user_data(marker):
    src = _SERVER.replace("__MARKER__", marker).replace("__SLEEP__", str(_SLEEP_S))
    return ("#!/bin/bash\ncat > /opt/sim2real_srv.py <<'PYEOF'\n" + src
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
    "InvalidSubnetID.NotFound", "InvalidAssociationID.NotFound", "ListenerNotFound"})


def _quiet(fn):
    """Teardown: tolerate only an already-gone resource; raise every other failure."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _GONE:
                raise
    return _wrapped


def _http(ctx, url, timeout=30):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers=_route)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _timed_get(ctx, host, path, timeout=30):
    """(status, body, seconds from sending the request to reading the reply). The DNS lookup
    and TCP connect happen first and are not timed, so a slow connect is not counted as the
    load balancer's reply time."""
    _url, _route = ctx.endpoint_route(f"http://{host}")
    _t = urllib.parse.urlsplit(_url)
    conn = http.client.HTTPConnection(_t.hostname, _t.port or 80, timeout=timeout)
    try:
        conn.connect()
        started = time.monotonic()
        conn.request("GET", path, headers=_route)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body, time.monotonic() - started
    finally:
        conn.close()


def _reachable(ctx, url):
    """Status of one request, or the error text while the load balancer's name or listener is not yet
    reachable; for warm-up polls only."""
    try:
        return _http(ctx, url, timeout=15)[0]
    except (urllib.error.URLError, OSError) as exc:
        return f"unreachable: {exc}"


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
        for _ in range(20):
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
    return iid


def _drop_instances(ctx, ids):
    """One net for every instance appended to `ids`: terminate all first, then wait once."""
    ec2 = ctx.client("ec2")

    def _drop():
        if not ids:
            return
        try:
            ec2.terminate_instances(InstanceIds=list(ids))
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=list(ids), WaiterConfig={"Delay": 2, "MaxAttempts": 200})
        except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
            teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if teardown_code not in ("InvalidInstanceID.NotFound",):
                raise RuntimeError(
                    f"instances {ids!r} termination not confirmed: {exc}"
                ) from exc

    ctx.on_cleanup(_drop)


def _load_balancer(ctx, subnets, sg):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-olb-")
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
    name = ctx.unique_name("sim2real-otg-")
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
    elb.modify_target_group_attributes(TargetGroupArn=arn, Attributes=[
        {"Key": "deregistration_delay.timeout_seconds", "Value": "5"}])
    return name, arn


def _listener(ctx, lb_arn, tg_arn):
    elb = ctx.client("elbv2")
    arn = elb.create_listener(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[
        {"Type": "forward", "TargetGroupArn": tg_arn}])["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_quiet(lambda: elb.delete_listener(ListenerArn=arn)))
    return arn


def _wait_lb_active(ctx, arn):
    elb = ctx.client("elbv2")
    lb = _poll_until(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
                     lambda x: x["State"]["Code"] in ("active", "failed"), timeout_s=600,
                     interval_s=10, description="load balancer leaving 'provisioning'")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _wait_healthy(ctx, tg_arn, ids):
    elb = ctx.client("elbv2")

    def _states():
        return {d["Target"]["Id"]: d["TargetHealth"]["State"] for d in
                elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]}

    return _poll_until(_states, lambda s: all(s.get(i) == "healthy" for i in ids),
                       timeout_s=720, interval_s=10,
                       description=f"targets {ids!r} reaching 'healthy' in {tg_arn}")


def _stat(ctx, metric, dims, start, statistic="Sum"):
    """Total of one statistic over every 60 s datapoint from `start` to now+3 min."""
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=_NS, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=[statistic])["Datapoints"]
    return sum(p[statistic] for p in pts)


def _dimension_sets(ctx, metric, lb_dim):
    """Every dimension-NAME set under which `metric` is catalogued for THIS load balancer, plus
    the AvailabilityZone values seen. Scoped by our own LoadBalancer value, so the result is a
    property of the query, not of what else the account holds."""
    pager = ctx.client("cloudwatch").get_paginator("list_metrics")
    sets, azs = set(), set()
    for page in pager.paginate(Namespace=_NS, MetricName=metric,
                               Dimensions=[{"Name": "LoadBalancer", "Value": lb_dim}]):
        for m in page["Metrics"]:
            names = frozenset(d["Name"] for d in m["Dimensions"])
            sets.add(names)
            azs.update(d["Value"] for d in m["Dimensions"] if d["Name"] == "AvailabilityZone")
    return sets, azs


def _align_minute(margin_s=3, guard_s=20):
    """Block until `margin_s` into a fresh UTC minute that begins at least `guard_s` after now,
    and return that minute, so every warm-up request lands in an EARLIER 60 s bucket than the
    measured batch. A computed alignment with a deadline, not a fixed sleep."""
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


def _malformed(ctx, host):
    """One TCP connection carrying a request line that is not HTTP; returns the raw reply."""
    with socket.create_connection(ctx.endpoint_host(host, 80), timeout=15) as s:
        s.sendall(b"THIS-IS-NOT-HTTP \x01\x02 garbage\r\n\r\n")
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)
# ===== end helpers =====


def _body(ctx) -> None:
    """An ALB in front of two EC2 targets files load-balancer-generated outcomes and connection
    reuse into AWS/ApplicationELB exactly, on the literal ``app/<name>/<id>`` dimension:

      1. N1 raw-socket requests whose request line is not HTTP are REJECTED by the load balancer
         with 400: ``HTTPCode_ELB_4XX_Count == N1``, they are absent from ``RequestCount`` (no
         target was chosen) and ``HTTPCode_Target_4XX_Count == 0`` (no target ever saw them).
      2. N2 requests to a path the target answers only after sleeping past the load balancer's
         ``idle_timeout.timeout_seconds=1`` come back 504 from the load balancer:
         ``HTTPCode_ELB_504_Count == N2 == HTTPCode_ELB_5XX_Count``, ``HTTPCode_ELB_502_Count ==
         0`` and ``HTTPCode_Target_5XX_Count == 0``. These DID choose a target, so
         ``RequestCount == N2 + N3`` exactly.
      3. N3 requests on ONE client keep-alive connection make ``NewConnectionCount`` smaller than
         ``RequestCount``.
      4. ``list_metrics`` catalogues each of those metrics under EXACTLY the expected dimension-
         name sets for this load balancer, no more and no fewer.

    No API response shows any of this: every claim is about CloudWatch series that exist only because
    traffic crossed the load balancer's data plane — a malformed request line on a raw socket, a
    target that outlives an idle timeout, TCP connection reuse — keyed by a dimension string no ELBv2
    API response returns in that form. The shipped sibling covers target-generated codes only.

    Negative half and its control: the malformed requests must be rejected with no effect on any
    target-scoped series, while the well-formed requests in the same minute are counted.
    The load balancer admits only the runner's ingress ranges, so the load-balancer-scoped series
    hold this run's traffic alone.
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")

    azs = _usable_azs(ec2, "t3.micro", 2)
    ami = _al2023_ami(ec2)
    vpc, subnets = _network(ctx, azs, 62)
    alb_sg = _security_group(ctx, vpc, "sim2real alb ingress from this run only", lambda sg: {
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    tgt_sg = _security_group(ctx, vpc, "sim2real target ingress from alb", lambda sg: {
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "UserIdGroupPairs": [{"GroupId": alb_sg}]})

    instance_ids = []
    _drop_instances(ctx, instance_ids)  # one net, registered before the first create
    iid_a = _instance(ctx, ami, subnets[0], tgt_sg, "A")
    instance_ids.append(iid_a)
    iid_b = _instance(ctx, ami, subnets[1], tgt_sg, "B")
    instance_ids.append(iid_b)
    lb_name, lb = _load_balancer(ctx, subnets, alb_sg)
    lb_arn = lb["LoadBalancerArn"]
    tg_name, tg_arn = _target_group(ctx, vpc)
    _listener(ctx, lb_arn, tg_arn)

    elb.modify_load_balancer_attributes(LoadBalancerArn=lb_arn, Attributes=[
        {"Key": "idle_timeout.timeout_seconds", "Value": str(_IDLE_S)}])
    attrs = {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn)["Attributes"]}
    assert attrs.get("idle_timeout.timeout_seconds") == str(_IDLE_S), (
        f"idle_timeout.timeout_seconds reads back {attrs.get('idle_timeout.timeout_seconds')!r}, "
        f"expected {str(_IDLE_S)!r}")

    ec2.get_waiter("instance_running").wait(InstanceIds=[iid_a, iid_b],
                                            WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": iid_a}, {"Id": iid_b}])
    _wait_lb_active(ctx, lb_arn)
    _wait_healthy(ctx, tg_arn, [iid_a, iid_b])

    lb_id = lb_arn.rsplit("/", 1)[-1]
    lb_dim = f"app/{lb_name}/{lb_id}"
    assert lb_arn.endswith(":loadbalancer/" + lb_dim), f"LB ARN {lb_arn!r} does not end in {lb_dim!r}"

    host = lb["DNSName"]
    base = f"http://{host}"
    _poll_until(lambda: _reachable(ctx, f"{base}/warm/ok"), lambda s: s == 200, timeout_s=180,
                interval_s=3, description="the listener forwarding to the healthy targets")
    # ---- measured batch: every request lands in minutes >= t0 -----------------------------
    t0 = _align_minute()

    for i in range(_N_BAD):
        reply = _malformed(ctx, host)
        assert reply.startswith(b"HTTP/1.1 400"), (
            f"malformed request {i}: the load balancer replied {reply[:120]!r}, expected an "
            f"HTTP/1.1 400 it generated itself")
        assert b"TARGET-" not in reply, f"malformed request {i} reached a target: {reply[:200]!r}"

    for i in range(_N_SLOW):
        status, body, took = _timed_get(ctx, host, "/m/slow")
        assert status == 504 and b"TARGET-" not in body, (
            f"slow request {i} returned {status} {body[:80]!r} after {took:.1f}s, expected the "
            f"load balancer's own 504 once the {_IDLE_S}s idle timeout lapsed")
        assert took < _SLEEP_S, (
            f"slow request {i} took {took:.1f}s: the 504 must arrive before the target's "
            f"{_SLEEP_S}s reply, i.e. on the idle timeout")

    _url, _route = ctx.endpoint_route(f"http://{host}")
    _t = urllib.parse.urlsplit(_url)
    conn = http.client.HTTPConnection(_t.hostname, _t.port or 80, timeout=15)
    try:
        ports = set()
        for i in range(_N_KEEP):
            conn.request("GET", f"/m/keep/{i}", headers=_route)
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200 and body.startswith(b"TARGET-200:"), (
                f"keep-alive request {i} returned {resp.status} {body[:60]!r}")
            assert (resp.getheader("Connection") or "").lower() != "close", (
                f"keep-alive request {i}: the load balancer asked to close the connection")
            ports.add(conn.sock.getsockname()[1])
        assert len(ports) == 1, (
            f"the {_N_KEEP} keep-alive requests used local ports {sorted(ports)!r}; they must all "
            f"ride one TCP connection")
    finally:
        conn.close()

    n_requests = _N_SLOW + _N_KEEP
    lbd = [{"Name": "LoadBalancer", "Value": lb_dim}]
    obs = {}

    obs["RequestCount"] = _poll_until(
        lambda: _stat(ctx, "RequestCount", lbd, t0), lambda v: v >= n_requests, timeout_s=600,
        interval_s=15, description=f"RequestCount{{LoadBalancer={lb_dim}}} reaching {n_requests}")
    obs["HTTPCode_ELB_4XX_Count"] = _poll_until(
        lambda: _stat(ctx, "HTTPCode_ELB_4XX_Count", lbd, t0), lambda v: v >= _N_BAD,
        timeout_s=600, interval_s=15, description=f"HTTPCode_ELB_4XX_Count reaching {_N_BAD}")
    obs["HTTPCode_ELB_504_Count"] = _poll_until(
        lambda: _stat(ctx, "HTTPCode_ELB_504_Count", lbd, t0), lambda v: v >= _N_SLOW,
        timeout_s=600, interval_s=15, description=f"HTTPCode_ELB_504_Count reaching {_N_SLOW}")
    obs["HTTPCode_ELB_5XX_Count"] = _poll_until(
        lambda: _stat(ctx, "HTTPCode_ELB_5XX_Count", lbd, t0), lambda v: v >= _N_SLOW,
        timeout_s=600, interval_s=15, description=f"HTTPCode_ELB_5XX_Count reaching {_N_SLOW}")
    obs["NewConnectionCount"] = _poll_until(
        lambda: _stat(ctx, "NewConnectionCount", lbd, t0), lambda v: v >= _N_SLOW + 1,
        timeout_s=600, interval_s=15,
        description=f"NewConnectionCount reaching at least the {_N_SLOW + 1} well-formed connections")
    obs["HTTPCode_Target_2XX_Count"] = _poll_until(
        lambda: _stat(ctx, "HTTPCode_Target_2XX_Count", lbd, t0), lambda v: v >= _N_KEEP,
        timeout_s=600, interval_s=15, description=f"HTTPCode_Target_2XX_Count reaching {_N_KEEP}")
    # Read AFTER every series from the same minutes has landed, so a zero is a decision.
    for m in ("HTTPCode_Target_4XX_Count", "HTTPCode_Target_5XX_Count", "HTTPCode_ELB_502_Count"):
        obs[m] = _stat(ctx, m, lbd, t0)

    assert obs["HTTPCode_ELB_4XX_Count"] == _N_BAD, (
        f"HTTPCode_ELB_4XX_Count = {obs['HTTPCode_ELB_4XX_Count']}, expected exactly {_N_BAD} "
        f"malformed requests rejected by the load balancer; all observations {obs!r}")
    assert obs["RequestCount"] == n_requests, (
        f"RequestCount = {obs['RequestCount']}, expected exactly {n_requests} (= {_N_SLOW} timed-out "
        f"+ {_N_KEEP} keep-alive); {_N_BAD} malformed requests chose no target and must be excluded; "
        f"all observations {obs!r}")
    assert obs["HTTPCode_Target_4XX_Count"] == 0, (
        f"HTTPCode_Target_4XX_Count = {obs['HTTPCode_Target_4XX_Count']}: the malformed requests "
        f"never reached a target; all observations {obs!r}")
    assert obs["HTTPCode_ELB_504_Count"] == _N_SLOW == obs["HTTPCode_ELB_5XX_Count"], (
        f"ELB 504={obs['HTTPCode_ELB_504_Count']} 5XX={obs['HTTPCode_ELB_5XX_Count']}, expected both "
        f"exactly {_N_SLOW}; all observations {obs!r}")
    assert obs["HTTPCode_ELB_502_Count"] == 0 and obs["HTTPCode_Target_5XX_Count"] == 0, (
        f"an idle-timeout is a 504, never a 502, and the target never answered: "
        f"ELB_502={obs['HTTPCode_ELB_502_Count']} Target_5XX={obs['HTTPCode_Target_5XX_Count']}; "
        f"all observations {obs!r}")
    assert obs["HTTPCode_Target_2XX_Count"] == _N_KEEP, (
        f"HTTPCode_Target_2XX_Count = {obs['HTTPCode_Target_2XX_Count']}, expected {_N_KEEP}: the "
        f"timed-out requests' late target replies were discarded, not counted; all {obs!r}")
    assert obs["NewConnectionCount"] < obs["RequestCount"], (
        f"NewConnectionCount = {obs['NewConnectionCount']} is not below RequestCount = "
        f"{obs['RequestCount']}: {_N_KEEP} requests rode one keep-alive connection; all {obs!r}")

    # ---- list_metrics: the exact dimension-name sets per metric, for this load balancer -------
    lb_only = frozenset({"LoadBalancer"})
    lb_az = frozenset({"LoadBalancer", "AvailabilityZone"})
    lb_tg = frozenset({"LoadBalancer", "TargetGroup"})
    lb_tg_az = frozenset({"LoadBalancer", "TargetGroup", "AvailabilityZone"})
    expected = {
        "RequestCount": {lb_only, lb_az, lb_tg, lb_tg_az},
        "HTTPCode_ELB_4XX_Count": {lb_only, lb_az},
        "HTTPCode_ELB_504_Count": {lb_only, lb_az},
        "HTTPCode_ELB_5XX_Count": {lb_only, lb_az},
        "NewConnectionCount": {lb_only, lb_az},
    }
    catalogue = {}
    for metric, want in expected.items():
        got, seen_azs = _poll_until(
            lambda m=metric: _dimension_sets(ctx, m, lb_dim), lambda r, w=want: w <= r[0],
            timeout_s=600, interval_s=20,
            description=f"list_metrics cataloguing {metric} under {sorted(map(sorted, want))!r}")
        catalogue[metric] = (got, seen_azs)
    for metric, want in expected.items():
        got, seen_azs = catalogue[metric]
        assert got == want, (
            f"list_metrics catalogues {metric} for {lb_dim!r} under dimension sets "
            f"{sorted(map(sorted, got))!r}, expected exactly {sorted(map(sorted, want))!r}")
        assert seen_azs and seen_azs <= set(azs), (
            f"{metric}'s AvailabilityZone values {sorted(seen_azs)!r} must be a non-empty subset "
            f"of the zone NAMES the subnets were created in, {azs!r}")


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
