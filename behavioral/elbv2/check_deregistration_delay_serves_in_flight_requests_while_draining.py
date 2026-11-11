"""deregistration-delay-serves-in-flight-requests-while-draining."""
from __future__ import annotations

import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregistration-delay-serves-in-flight-requests-while-draining"
GROUP = 'state-machine'
SERVICES = ['elbv2']

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _own_vpc_and_subnets(ctx, num_subnets=2):
    """A routable VPC and public subnets this check creates for the internet-facing load balancer."""
    return _own_public_vpc(ctx, n_subnets=num_subnets)


def _http_sg(ctx, vpc_id, source, ports=(80,)):
    """A security group admitting tcp *ports* from *source* (IpRanges or UserIdGroupPairs)."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _net_safe_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))()

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": p, "ToPort": p, **source,
        } for p in ports],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Create the load balancer and register its waited teardown immediately."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(
        Name=name, Subnets=subnet_ids, Type="application",
        Scheme="internal", Tags=list(_TAGS),
    )
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if _gone(exc):
                return
            raise
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if _gone(exc):
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"load balancer {arn} is still listed 180s after its delete")

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _fixed(body, status="200"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": "text/plain", "MessageBody": body}}]


def _create_rule(ctx, listener_arn, priority, path_values, body, status="200"):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{"Field": "path-pattern",
                     "PathPatternConfig": {"Values": list(path_values)}}],
        Actions=_fixed(body, status), Tags=list(_TAGS),
    ))["Rules"][0]
    arn = rule["RuleArn"]

    def _drop_rule():
        try:
            elb.delete_rule(RuleArn=arn)
        except ClientError as exc:
            if not _gone(exc):
                raise

    ctx.on_cleanup(_drop_rule)
    return rule


def _wait_for_body(ctx, url, expected, *, timeout_s=300, headers=None):
    """Poll until the load balancer serves exactly `expected` (body, or (status, body)).

    Configuration changes reach the data plane asynchronously, so this polls within a bound.
    """
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:40]}")
        return (status, body)

    def matches(r):
        if r is None:
            return False
        if isinstance(expected, tuple):
            return (r[0], r[1].strip()) == expected
        return r[1].strip() == expected

    return _poll_until(
        probe, matches, timeout_s=timeout_s, interval_s=5,
        description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
    )


_GONE_CODES = frozenset(
    {"Gateway.NotAttached", "NoSuchEntity", "AWS.SimpleQueueService.NonExistentQueue"})


def _gone(exc):
    """A teardown delete whose resource is already gone is done."""
    code = exc.response.get("Error", {}).get("Code", "")
    return code.endswith(("NotFound", "NotFoundException")) or code in _GONE_CODES


def _safe(fn):
    """Teardown: a resource that is already gone is done; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if not _gone(exc):
                raise

    return _wrapped


def _usable_az_subnets(ctx, vpc_id, want="t3.micro", n=2):
    """Subnets in AZs that really offer `want`.

    Instance type offerings do not report zone state, and an AZ without the type fails
    RunInstances with 'Unsupported'.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = offered & available
    assert usable, (
        f"no available AZ in {ctx.region} offers {want!r}; offerings were {sorted(offered)!r}"
    )
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]},
    ])["Subnets"]
    per_az = {}
    for sub in sorted(subnets, key=lambda s: s["SubnetId"]):
        if sub["AvailabilityZone"] in usable:
            per_az.setdefault(sub["AvailabilityZone"], sub["SubnetId"])
    picked = [per_az[az] for az in sorted(per_az)][:n]
    if len(picked) < n:
        raise AssertionError(
            f"VPC {vpc_id} exposes {len(picked)} subnets in AZs offering {want}, "
            f"need {n} (usable AZs: {sorted(usable)})"
        )
    return picked


def _describe_instance(ec2, iid, ctx=None):
    """DescribeInstances tolerating the eventual consistency right after RunInstances.

    AWS can return InvalidInstanceID.NotFound for an id RunInstances just returned.
    """
    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (120 if left is None else max(1.0, min(120, left - 5.0)))
    last = None
    while time.monotonic() < deadline:
        try:
            return ec2.describe_instances(InstanceIds=[iid])[
                "Reservations"][0]["Instances"][0]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise
            last = exc
        except (IndexError, KeyError) as exc:
            last = exc
        time.sleep(2)
    raise AssertionError(f"instance {iid} never appeared in DescribeInstances: {last!r}")


def _launch_backend(ctx, subnet_id, sg_id, user_data, *, want="t3.micro"):
    """One EC2 instance running an HTTP backend from user-data, tagged at creation.

    The AMI comes from the SSM public parameter because image ids are region-specific and go stale.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-behav-ec2-")
    tags = list(_TAGS) + [{"Key": "Name", "Value": name}]
    inst = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags},
            {"ResourceType": "volume", "Tags": tags},
        ],
    )["Instances"][0]
    iid = inst["InstanceId"]

    def _drop_instance():
        _safe(lambda: ec2.terminate_instances(InstanceIds=[iid]))()
        # Wait for 'terminated': the instance's ENI holds the security group, and an ENI holder
        # is the classic cause of a DependencyViolation on the security-group delete after this.
        state = None
        for _ in range(60):
            try:
                found = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
            except ClientError as exc:
                if _gone(exc):
                    return
                raise
            if not found:
                return
            state = found[0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            time.sleep(5)
        raise AssertionError(
            f"instance {iid} is {state!r}, not terminated, 300s after its terminate")

    ctx.on_cleanup(_drop_instance)
    _poll_until(
        lambda: _describe_instance(ec2, iid, ctx)["State"]["Name"],
        lambda s: s in ("running", "terminated", "shutting-down"),
        timeout_s=300, interval_s=5,
        description=f"instance {iid} reaching a terminal launch state",
    )
    described = _describe_instance(ec2, iid, ctx)
    assert described["State"]["Name"] == "running", (
        f"instance {iid} state {described['State']['Name']!r}, expected running"
    )
    return {"id": iid, "private_ip": described["PrivateIpAddress"]}


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # The deleted load balancer releases the group asynchronously: ResourceInUse is retried.
        for attempt in range(30):
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                if _gone(exc):
                    return
                code = exc.response.get("Error", {}).get("Code")
                if code != "ResourceInUse" or attempt == 29:
                    raise
            time.sleep(4)

    ctx.on_cleanup(_drop_tg)
    return tg


def _target_health(ctx, tg_arn, target):
    elb = ctx.client("elbv2")
    got = elb.describe_target_health(TargetGroupArn=tg_arn, Targets=[target])
    descs = got["TargetHealthDescriptions"]
    if not descs:
        return None
    return descs[0]["TargetHealth"]


def _wait_target_state(ctx, tg_arn, target, wanted, *, timeout_s=420):
    seen = []

    def probe():
        health = _target_health(ctx, tg_arn, target)
        seen.append(None if health is None else
                    f"{health.get('State')}/{health.get('Reason')}")
        return health

    return _poll_until(
        probe, lambda h: h is not None and h.get("State") == wanted,
        timeout_s=timeout_s, interval_s=5,
        description=f"target {target!r} in {tg_arn.rsplit('/', 2)[-2]} reaching state "
                    f"{wanted!r} (observed: {seen[-10:]})",
    )


def _forward(target_groups, sticky=None):
    cfg = {"TargetGroups": target_groups}
    if sticky is not None:
        cfg["TargetGroupStickinessConfig"] = sticky
    return [{"Type": "forward", "ForwardConfig": cfg}]


# ===== end helpers =====


#: One instance, two labelled backends. Port 80 answers TARGET-A, port 8080 answers TARGET-B,
#: and ?s=<seconds> makes either one slow. Two ports rather than two instances so the drained
#: group and the surviving group differ ONLY in which target group they belong to.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver
import threading
import time


def make(label):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            parts = self.path.split("?", 1)
            secs = 0.0
            if len(parts) > 1:
                for kv in parts[1].split("&"):
                    if kv.startswith("s="):
                        try:
                            secs = float(kv[2:])
                        except ValueError:
                            secs = 0.0
            time.sleep(secs)
            body = label.encode()
            self.send_response(200)
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


b = S(("", 8080), make("TARGET-B"))
threading.Thread(target=b.serve_forever, daemon=True).start()
S(("", 80), make("TARGET-A")).serve_forever()
PYEOF_INNER
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
"""

_DELAY_S = 60


def _inflight(target_url, host, path, out, sent):
    """Open a connection, send a request for a slow response, signal `sent`, then read the reply.

    A raw socket lets `sent` fire once the request is provably on the wire.
    """
    _t = urllib.parse.urlsplit(target_url)
    try:
        sock = socket.create_connection((_t.hostname, _t.port or 80), timeout=120)
    except OSError as exc:
        out["error"] = f"connect failed: {exc!r}"
        sent.set()
        return
    try:
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        sent.set()
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        out["raw"] = buf.decode("utf-8", "replace")
    except OSError as exc:
        out["error"] = f"read failed after {len(out.get('raw', ''))} bytes: {exc!r}"
    finally:
        sock.close()


def _parse_http(raw):
    head, _sep, body = raw.partition("\r\n\r\n")
    first = head.split("\r\n", 1)[0]
    parts = first.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return status, body


def _listed_targets(ctx, tg_arn):
    elb = ctx.client("elbv2")
    return {
        (d["Target"]["Id"], d["Target"].get("Port"))
        for d in elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    }


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html#deregistration-delay
@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5", "timing:real-time")
def run(ctx) -> None:
    """A deregistered target enters draining (Target.DeregistrationInProgress) and completes the
    in-flight request; after the delay it leaves the group, which then returns 503, while a second
    target group keeps serving.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html#deregistration-delay
    """
    elb = ctx.client("elbv2")
    vpc_id, _own_subnets = _own_vpc_and_subnets(ctx)
    subnet_ids = _usable_az_subnets(ctx, vpc_id, n=2)
    # The load balancer admits the caller; the backend admits only the load balancer's group.
    sg_id = _http_sg(ctx, vpc_id, {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _http_sg(ctx, vpc_id, {"UserIdGroupPairs": [{"GroupId": sg_id}]}, ports=(80, 8080))

    inst = _launch_backend(ctx, subnet_ids[0], be_sg, _USER_DATA)
    target_a = {"Id": inst["id"], "Port": 80}
    target_b = {"Id": inst["id"], "Port": 8080}

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg_a = _create_target_group(
        ctx, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/",
        HealthCheckIntervalSeconds=10, HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2,
    )
    tg_b = _create_target_group(
        ctx, Protocol="HTTP", Port=8080, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/",
        HealthCheckIntervalSeconds=10, HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2,
    )
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_a["TargetGroupArn"],
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(_DELAY_S)}]))
    stored = {a["Key"]: a["Value"] for a in elb.describe_target_group_attributes(
        TargetGroupArn=tg_a["TargetGroupArn"])["Attributes"]}
    assert stored.get("deregistration_delay.timeout_seconds") == str(_DELAY_S), (
        f"deregistration_delay.timeout_seconds reads {stored.get(
            'deregistration_delay.timeout_seconds')!r}, expected {str(_DELAY_S)!r}"
    )

    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_a["TargetGroupArn"], Targets=[target_a]))
    ctx.on_cleanup(_safe(lambda: elb.deregister_targets(
        TargetGroupArn=tg_a["TargetGroupArn"], Targets=[target_a])))
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_b["TargetGroupArn"], Targets=[target_b]))
    ctx.on_cleanup(_safe(lambda: elb.deregister_targets(
        TargetGroupArn=tg_b["TargetGroupArn"], Targets=[target_b])))

    def _weights(wa, wb):
        return _forward([
            {"TargetGroupArn": tg_a["TargetGroupArn"], "Weight": wa},
            {"TargetGroupArn": tg_b["TargetGroupArn"], "Weight": wb},
        ], sticky={"Enabled": False})

    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=_weights(1, 0),
    )
    la = listener["ListenerArn"]

    _wait_target_state(ctx, tg_a["TargetGroupArn"], target_a, "healthy")
    _wait_target_state(ctx, tg_b["TargetGroupArn"], target_b, "healthy")

    dns = lb["DNSName"]
    url = f"http://{dns}/"
    _wait_for_body(ctx, url, "TARGET-A")

    # Open a 25-second request THROUGH the load balancer and wait for the observable signal
    # that it is on the wire, then deregister underneath it.
    out = {}
    sent = threading.Event()
    target_url = ctx.endpoint_url(f"http://{dns}")
    worker = threading.Thread(target=_inflight, args=(target_url, dns, "/?s=25", out, sent), daemon=True)
    worker.start()
    assert sent.wait(60), "the in-flight request was never put on the wire"
    assert "error" not in out, f"the in-flight request failed before deregistration: {out!r}"

    _retry_throttled(lambda: elb.deregister_targets(
        TargetGroupArn=tg_a["TargetGroupArn"], Targets=[target_a]))
    draining = _wait_target_state(ctx, tg_a["TargetGroupArn"], target_a, "draining",
                                 timeout_s=180)
    draining_state = draining.get("State")
    assert draining_state == "draining", (
        f"the deregistered target reported State {draining_state!r}, expected draining"
    )
    draining_reason = draining.get("Reason")
    assert draining_reason == "Target.DeregistrationInProgress", (
        f"the draining target reported Reason {draining_reason!r}, expected "
        f"Target.DeregistrationInProgress"
    )

    # The request already in flight completes anyway. That is the whole point of the
    # deregistration delay.
    worker.join(120)
    assert not worker.is_alive(), f"the in-flight request never completed: {out!r}"
    assert "error" not in out, (
        f"the in-flight request did not survive the deregistration: {out!r}"
    )
    inflight_status, inflight_body = _parse_http(out.get("raw", ""))
    assert inflight_status == 200, (
        f"the in-flight request through the draining target returned HTTP "
        f"{inflight_status!r}, expected 200. Raw: {out.get('raw', '')[:300]!r}"
    )
    assert inflight_body.strip() == "TARGET-A", (
        f"a draining target did not finish serving the in-flight request: got "
        f"{inflight_body.strip()!r}, expected TARGET-A"
    )

    # After the delay the target is gone from the group altogether, not merely draining.
    # The effect-absent assertion waits for this: while it is the only target, a draining target
    # can still be routed new requests, but an empty group cannot fail open.
    remaining = _poll_until(
        lambda: _listed_targets(ctx, tg_a["TargetGroupArn"]),
        lambda s: (target_a["Id"], target_a["Port"]) not in s,
        timeout_s=_DELAY_S * 4, interval_s=5,
        description=f"the deregistered target leaving describe_target_health after the "
                    f"{_DELAY_S}s deregistration delay",
    )
    gone_after_delay = (target_a["Id"], target_a["Port"]) not in remaining
    assert gone_after_delay is True, (
        f"the target was still listed in describe_target_health after the {_DELAY_S}s "
        f"deregistration delay: {remaining!r}"
    )

    # EFFECT ABSENT: routing to the now-empty target group is refused, and the drained
    # target's body never appears again.
    seen503 = []

    def _probe_empty():
        try:
            status, _hdrs, body = _http(ctx, url, timeout=30)
        except (urllib.error.URLError, OSError) as exc:
            seen503.append(f"<transport: {exc}>")
            return None
        seen503.append(f"{status}:{body.strip()[:30]}")
        return (status, body)

    post_drain_status, post_drain_body = _poll_until(
        _probe_empty, lambda r: r is not None and r[0] != 200,
        timeout_s=240, interval_s=5,
        description=f"the load balancer refusing to route to the emptied target group "
                    f"(observed: {seen503[-8:]})",
    )
    assert post_drain_status == 503, (
        f"routing to the emptied target group returned HTTP {post_drain_status!r}, expected "
        f"503 once the drained target was gone"
    )
    assert "TARGET-A" not in post_drain_body, (
        f"the drained target still served content after leaving the target group: "
        f"{post_drain_body[:200]!r}"
    )

    # POSITIVE CONTROL: the second group never lost capacity, so the 503 above is the emptied
    # group's doing and not a broken load balancer.
    _retry_throttled(lambda: elb.modify_listener(ListenerArn=la, DefaultActions=_weights(0, 1)))
    _survivor_status, survivor_body = _wait_for_body(ctx, url, "TARGET-B")
    assert survivor_body.strip() == "TARGET-B", (
        f"the still-registered target stopped serving: got {survivor_body.strip()!r}, "
        f"expected TARGET-B"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

# ===== own network (self-contained) =====

_NET_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _net_safe_cleanup(fn):
    """Teardown: a resource that is already gone is done; any other failure raises."""
    from botocore.exceptions import ClientError as _ClientError

    def _wrapped():
        try:
            fn()
        except _ClientError as exc:
            if not _gone(exc):
                raise

    return _wrapped


def _own_public_vpc(ctx, cidr="10.175.0.0/16", n_subnets=2, want="t3.micro"):
    """A VPC this check creates, with an internet gateway and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_NET_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    ]
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    azs = sorted(z for z in azs if z in offered)
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs offering {want}, need {n_subnets}")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _net_safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _net_safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(_net_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_net_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


# Network deletes wait (bounded) for the ENIs a load balancer or function leaves behind, retrying
# DependencyViolation inside one shared window, and raise naming the ENIs still attached.
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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]
