"""log-edge-producers-alb-access-log-502-record-differs-from-target-status."""
from __future__ import annotations

import datetime as _dt
import gzip
import json
import re
import socket
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-edge-producers-alb-access-log-502-record-differs-from-target-status"
GROUP = "access-logs"
SERVICES = ["elbv2", "s3"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_LOG_DELIVERY_PRINCIPAL = "logdelivery.elasticloadbalancing.amazonaws.com"
_CIDR = "10.178.0.0/16"
_AL2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

#: The documented ALB access-log field order. AWS only ever APPENDS to it, so these positions are
#: the contract Athena tables are built on; anything past the last name is not asserted.
_FIELDS = (
    "type", "time", "elb", "client:port", "target:port", "request_processing_time",
    "target_processing_time", "response_processing_time", "elb_status_code",
    "target_status_code", "received_bytes", "sent_bytes", "request", "user_agent", "ssl_cipher",
    "ssl_protocol", "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn",
    "matched_rule_priority", "request_creation_time", "actions_executed", "redirect_url",
    "error_reason", "target:port_list", "target_status_code_list", "classification",
    "classification_reason", "conn_trace_id",
)
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^ ]+')
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SECONDS = re.compile(r"^\d+\.\d{3}$")


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retrying_delete(what, fn, *, attempts=40, interval_s=8):
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
                if code.endswith("NotFound") or code.endswith(".NotFound") or code == "NoSuchBucket":
                    return
                last = exc
            time.sleep(interval_s)
        raise RuntimeError(f"{what}: {last!r}")

    return _wrapped


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-lel-logs-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)

    def _empty():
        s3.delete_bucket_policy(Bucket=name)
        while True:
            listing = s3.list_objects_v2(Bucket=name, MaxKeys=1000)
            keys = [{"Key": o["Key"]} for o in listing.get("Contents") or []]
            if not keys:
                break
            s3.delete_objects(Bucket=name, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=name)

    # Re-empties on every attempt: a final log flush can land after the load balancer is gone.
    ctx.on_cleanup(_retrying_delete(f"s3 bucket {name}", _empty, attempts=15, interval_s=10))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": list(_TAGS)})
    return name


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
        ctx.on_cleanup(_retrying_delete(
            f"subnet {sid}", lambda s=sid: ec2.delete_subnet(SubnetId=s)))
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_retrying_delete(
            f"rtb association {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a), attempts=3))
        subnets.append(sid)
    return vpc_id, subnets


def _security_group(ctx, vpc_id, name_prefix, ingress):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(name_prefix), Description="sim2real alb access-log check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_retrying_delete(
        f"security group {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
    return sg_id


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
        f"with an instance target needs {n}"
    )
    return usable[:n]


def _launch_backend(ctx, subnet_id, sg_id, user_data, want="t3.micro"):
    """One EC2 instance, tagged AT CREATION (the only cleanup handle), waited to terminated."""
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(Name=_AL2023)["Parameter"]["Value"]
    tagset = list(_TAGS) + [{"Key": "Name", "Value": ctx.unique_name("sim2real-lel-ec2-")}]
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1, UserData=user_data,
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
        for _ in range(225):
            inst = _state()
            if inst is None or inst["State"]["Name"] == "terminated":
                return
            time.sleep(2)
        raise RuntimeError(f"instance {iid} not terminated after 450s")

    ctx.on_cleanup(_drop_instance)
    inst = _poll_until(ctx, _state, lambda i: i is not None and i["State"]["Name"] != "pending",
                       timeout_s=300, interval_s=2, description=f"instance {iid} leaving pending")
    assert inst["State"]["Name"] == "running", (
        f"instance {iid} is {inst['State']['Name']!r}, expected 'running'")
    return iid, inst["PrivateIpAddress"]


def _create_load_balancer(ctx, subnets, sg_id):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lel-")
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
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(4)
        raise RuntimeError(f"load balancer {arn} still described after 360s")

    ctx.on_cleanup(_drop_lb)
    lb = _poll_until(
        ctx,
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning", timeout_s=600, interval_s=2,
        description=f"load balancer {name} leaving provisioning")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_target_group(ctx, vpc_id, port, health_port):
    elb = ctx.client("elbv2")
    tg = _retry_throttled(lambda: elb.create_target_group(
        Name=ctx.unique_name("sim2real-lel-tg-"), Protocol="HTTP", Port=port, VpcId=vpc_id,
        TargetType="instance", HealthCheckProtocol="HTTP", HealthCheckPort=str(health_port),
        HealthCheckPath="/health", HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2,
        HealthyThresholdCount=2, Tags=list(_TAGS)))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(_retrying_delete(
        f"target group {arn}", lambda: elb.delete_target_group(TargetGroupArn=arn), attempts=15))
    return arn


def _wait_healthy(ctx, tg_arn, target):
    elb = ctx.client("elbv2")
    seen = []

    def probe():
        d = elb.describe_target_health(TargetGroupArn=tg_arn, Targets=[target])
        h = d["TargetHealthDescriptions"][0]["TargetHealth"]
        seen.append(f"{h.get('State')}/{h.get('Reason')}")
        return h.get("State")

    _poll_until(ctx, probe, lambda s: s == "healthy", timeout_s=600, interval_s=2,
                description=f"target {target!r} healthy (observed {seen[-5:]!r})")


def _raw_get(ctx, host, path, user_agent):
    """One HTTP/1.1 request over a raw socket, so the exact bytes sent and received are KNOWN —
    received_bytes and sent_bytes are then derived rather than guessed."""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii")
    with socket.create_connection(ctx.endpoint_host(host, 80), timeout=20) as sock:
        sock.sendall(req)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    resp = b"".join(chunks)
    head, _, body = resp.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else None
    return {"sent": len(req), "received": len(resp), "status": status,
            "body": body.decode("utf-8", "replace")}


def _parse_record(line):
    """Split one entry on single spaces, honouring double-quoted fields, and REFUSE any line whose
    tokens do not re-join to the exact line — so an empty field (two adjacent spaces) cannot be
    silently dropped and shift every later position."""
    raw = _TOKEN.findall(line)
    assert " ".join(raw) == line, (
        f"access-log line is not strictly single-space separated tokens (an empty field?): "
        f"{line!r}")
    values = [t[1:-1] if len(t) >= 2 and t[0] == '"' and t[-1] == '"' else t for t in raw]
    assert len(values) >= len(_FIELDS), (
        f"access-log line has {len(values)} fields, expected at least {len(_FIELDS)}: {line!r}")
    return dict(zip(_FIELDS, values)), values


def _log_objects(ctx, bucket, account):
    s3 = ctx.client("s3")
    out = []
    kwargs = {"Bucket": bucket, "Prefix": f"AWSLogs/{account}/elasticloadbalancing/"}
    while True:
        listing = s3.list_objects_v2(**kwargs)
        for obj in listing.get("Contents") or []:
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            assert raw[:2] == b"\x1f\x8b", (
                f"access-log object {obj['Key']!r} is not gzip; first bytes {raw[:8]!r}")
            for line in gzip.decompress(raw).decode("utf-8").splitlines():
                if line.strip():
                    out.append((obj["Key"], line))
        if not listing.get("NextContinuationToken"):
            return out
        kwargs["ContinuationToken"] = listing["NextContinuationToken"]


def _iso(value):
    return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)


_BROKEN_PORT = 8081
#: Port 80 answers /health and echoes, as JSON, the headers the ALB ADDED on the way in
#: (X-Forwarded-For, X-Amzn-Trace-Id) — the target-side half of the join asserted against the log.
#: Port 8081 is the deliberately broken target: it reads the request, writes bytes that are not an
#: HTTP response, and closes. Its target group health-checks on port 80, so the target is HEALTHY
#: and routable; only its answer to real traffic is broken.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF'
import http.server, json, socket, socketserver, threading

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path == "/health":
            body = b"ok"
        else:
            body = json.dumps({"path": self.path,
                               "xff": self.headers.get("X-Forwarded-For"),
                               "trace": self.headers.get("X-Amzn-Trace-Id"),
                               "ua": self.headers.get("User-Agent")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def broken():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("", %d))
    ls.listen(64)
    while True:
        c, _ = ls.accept()
        try:
            c.settimeout(5)
            c.recv(65536)
            c.sendall(b"THIS IS NOT AN HTTP RESPONSE\\r\\n\\r\\n")
        except OSError:
            pass
        finally:
            c.close()

threading.Thread(target=broken, daemon=True).start()
S(("", 80), H).serve_forever()
PYEOF
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
""" % _BROKEN_PORT


# timing:real-time — buffer: 178 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """An ALB access-log record for a request a healthy target answered with non-HTTP bytes logs 502
    in elb_status_code and '-' in target_status_code, while the positive control logs 200 in both;
    every documented field of the records is asserted by position against what this check caused.
    """
    elb = ctx.client("elbv2")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    run_start = _dt.datetime.now(_dt.timezone.utc)

    azs = _usable_azs(ctx)
    bucket = _create_bucket(ctx)
    vpc_id, subnets = _own_vpc(ctx, azs)
    lb_sg = _security_group(ctx, vpc_id, "sim2real-lel-lbsg-", [
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    be_sg = _security_group(ctx, vpc_id, "sim2real-lel-besg-", [
        {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "UserIdGroupPairs": [{"GroupId": lb_sg}]}
        for p in (80, _BROKEN_PORT)])
    iid, private_ip = _launch_backend(ctx, subnets[0], be_sg, _USER_DATA)

    lb = _create_load_balancer(ctx, subnets, lb_sg)
    lb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]
    partition = lb_arn.split(":")[1]
    lb_id = lb_arn.split(":loadbalancer/", 1)[1]           # app/<name>/<id>

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": _LOG_DELIVERY_PRINCIPAL},
                       "Action": "s3:PutObject",
                       "Resource": f"arn:{partition}:s3:::{bucket}/AWSLogs/{account}/*"}],
    }))

    def _enable():
        try:
            return elb.modify_load_balancer_attributes(LoadBalancerArn=lb_arn, Attributes=[
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": bucket}])["Attributes"]
        except ClientError as exc:
            # Bucket-policy propagation only; any other refusal fails immediately.
            if exc.response.get("Error", {}).get("Code") == "InvalidConfigurationRequest":
                return None
            raise

    _poll_until(ctx, _enable, lambda a: a is not None, timeout_s=180, interval_s=2,
                description="access logging accepted once the bucket policy grants log delivery")
    ctx.on_cleanup(_retrying_delete(
        "disable access logs", lambda: elb.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[{"Key": "access_logs.s3.enabled", "Value": "false"}]), attempts=3))

    ok_tg = _create_target_group(ctx, vpc_id, 80, 80)
    bad_tg = _create_target_group(ctx, vpc_id, _BROKEN_PORT, 80)
    elb.register_targets(TargetGroupArn=ok_tg, Targets=[{"Id": iid, "Port": 80}])
    elb.register_targets(TargetGroupArn=bad_tg, Targets=[{"Id": iid, "Port": _BROKEN_PORT}])
    listener = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": ok_tg}])["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(_retrying_delete(
        "listener", lambda: elb.delete_listener(ListenerArn=listener_arn), attempts=3))
    marker = ctx.unique_name("m")
    rule_arn = elb.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": [f"/{marker}-broken/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": bad_tg}])["Rules"][0]["RuleArn"]
    ctx.on_cleanup(_retrying_delete(
        "listener rule", lambda: elb.delete_rule(RuleArn=rule_arn), attempts=3))
    _wait_healthy(ctx, ok_tg, {"Id": iid, "Port": 80})
    _wait_healthy(ctx, bad_tg, {"Id": iid, "Port": _BROKEN_PORT})

    plain_ua = f"sim2real-lel/{marker}"
    odd_ua = f"Mozilla/5.0 (sim2real; log-edge {marker}) probe/1.0"

    def _get(path, ua):
        try:
            return _raw_get(ctx, dns, path, ua)
        except OSError as exc:            # DNS not yet published, or the listener not yet serving
            return {"status": None, "error": repr(exc)}

    _poll_until(ctx, lambda: _get(f"/{marker}/warm", plain_ua), lambda r: r.get("status") == 200,
                timeout_s=420, interval_s=2, description="the ALB serving the healthy target")

    ok_path = f"/{marker}/ok"
    ua_path = f"/{marker}/ua?alpha=1&beta=two%20words"
    bad_path = f"/{marker}-broken/x"
    ok = _get(ok_path, plain_ua)
    ua = _get(ua_path, odd_ua)
    bad = _get(bad_path, plain_ua)
    sent_at_end = _dt.datetime.now(_dt.timezone.utc)

    # Positive control and the broken link, as the CLIENT saw them.
    assert ok.get("status") == 200, f"healthy-target request returned {ok!r}, expected 200"
    assert ua.get("status") == 200, f"query-string request returned {ua!r}, expected 200"
    assert bad.get("status") == 502, (
        f"request routed to the target that answers non-HTTP bytes returned {bad!r}, expected the "
        f"load balancer's own 502")
    ok_echo, ua_echo = json.loads(ok["body"]), json.loads(ua["body"])
    assert ua_echo["path"] == ua_path and ua_echo["ua"] == odd_ua, (
        f"target saw path/ua {ua_echo!r}, expected {ua_path!r} / {odd_ua!r}")

    wanted = {ok_path: "ok", ua_path: "ua", bad_path: "bad"}

    def _mine():
        found = {}
        for key, line in _log_objects(ctx, bucket, account):
            rec, values = _parse_record(line)
            path = rec["request"].split(" ")[1].split(f"{dns}:80", 1)[-1] \
                if rec["request"].count(" ") == 2 else None
            if path in wanted:
                found.setdefault(wanted[path], []).append((key, line, rec, values))
        return found

    found = _poll_until(ctx, _mine, lambda f: len(f) == 3, timeout_s=1200, interval_s=2,
                        description=f"access-log records for all three requests in s3://{bucket}")
    for label, recs in found.items():
        print(f"[record:{label}] {recs[0][1]}")
        assert len(recs) == 1, (
            f"{label!r} request produced {len(recs)} access-log records, expected exactly 1: "
            f"{[r[1] for r in recs]!r}")

    ok_rec, ua_rec, bad_rec = found["ok"][0][2], found["ua"][0][2], found["bad"][0][2]

    # ---- THE CORE CLAIM: the proxy's status and the target's status are logged separately. -----
    assert (bad_rec["elb_status_code"], bad_rec["target_status_code"]) == ("502", "-"), (
        f"502 record logs elb/target status {bad_rec['elb_status_code']!r}/"
        f"{bad_rec['target_status_code']!r}, expected '502'/'-' (the target never produced a "
        f"status line); record {found['bad'][0][1]!r}")
    assert bad_rec["target_status_code_list"] == "-", (
        f"502 record target_status_code_list is {bad_rec['target_status_code_list']!r}, expected '-'")
    for label, rec in (("ok", ok_rec), ("ua", ua_rec)):
        assert (rec["elb_status_code"], rec["target_status_code"]) == ("200", "200"), (
            f"{label} record logs elb/target status {rec['elb_status_code']!r}/"
            f"{rec['target_status_code']!r}, expected '200'/'200'")
        assert rec["target_status_code_list"] == "200", (
            f"{label} record target_status_code_list is {rec['target_status_code_list']!r}")

    # ---- which target answered: port and target group by position. ------------------------------
    for label, rec, port, tg in (("ok", ok_rec, 80, ok_tg), ("ua", ua_rec, 80, ok_tg),
                                 ("bad", bad_rec, _BROKEN_PORT, bad_tg)):
        want_target = f"{private_ip}:{port}"
        assert rec["target:port"] == want_target, (
            f"{label} record target:port is {rec['target:port']!r}, expected {want_target!r}")
        assert rec["target:port_list"] == want_target, (
            f"{label} record target:port_list is {rec['target:port_list']!r}, expected "
            f"{want_target!r}")
        assert rec["target_group_arn"] == tg, (
            f"{label} record target_group_arn is {rec['target_group_arn']!r}, expected {tg!r}")
        assert rec["matched_rule_priority"] == ("10" if label == "bad" else "0"), (
            f"{label} record matched_rule_priority is {rec['matched_rule_priority']!r}")
        assert rec["actions_executed"] == "forward", (
            f"{label} record actions_executed is {rec['actions_executed']!r}, expected 'forward'")

    # ---- the bytes this check put on the wire, and the request line it sent. --------------------
    for label, rec, sent, path, agent in (("ok", ok_rec, ok, ok_path, plain_ua),
                                          ("ua", ua_rec, ua, ua_path, odd_ua),
                                          ("bad", bad_rec, bad, bad_path, plain_ua)):
        assert rec["type"] == "http", f"{label} record type is {rec['type']!r}, expected 'http'"
        assert rec["elb"] == lb_id, f"{label} record elb is {rec['elb']!r}, expected {lb_id!r}"
        want_line = f"GET http://{dns}:80{path} HTTP/1.1"
        assert rec["request"] == want_line, (
            f"{label} record request is {rec['request']!r}, expected {want_line!r}")
        assert rec["user_agent"] == agent, (
            f"{label} record user_agent is {rec['user_agent']!r}, expected {agent!r}")
        assert rec["received_bytes"] == str(sent["sent"]), (
            f"{label} record received_bytes is {rec['received_bytes']!r}; this check sent exactly "
            f"{sent['sent']} bytes")
        assert rec["sent_bytes"] == str(sent["received"]), (
            f"{label} record sent_bytes is {rec['sent_bytes']!r}; this check received exactly "
            f"{sent['received']} bytes")
        # Absent values are '-' — never an empty field (the parser already refused empties).
        for name in ("ssl_cipher", "ssl_protocol", "domain_name", "chosen_cert_arn",
                     "redirect_url", "classification", "classification_reason"):
            assert rec[name] == "-", (
                f"{label} record {name} is {rec[name]!r}, expected '-' on a plain-HTTP, RFC-"
                f"compliant request")
        assert _SECONDS.match(rec["request_processing_time"]), (
            f"{label} record request_processing_time is {rec['request_processing_time']!r}, "
            f"expected seconds with ms precision")
        assert _SECONDS.match(rec["target_processing_time"]), (
            f"{label} record target_processing_time is {rec['target_processing_time']!r}, expected "
            f"seconds with ms precision (the broken target DID answer, with non-HTTP bytes)")
        assert rec["error_reason"] == "-", (
            f"{label} record error_reason is {rec['error_reason']!r}, expected '-' for an instance "
            f"target")
        assert _ISO.match(rec["time"]) and _ISO.match(rec["request_creation_time"]), (
            f"{label} record time/request_creation_time {rec['time']!r}/"
            f"{rec['request_creation_time']!r} are not ISO-8601 microsecond UTC")
        t_resp, t_req = _iso(rec["time"]), _iso(rec["request_creation_time"])
        assert t_req <= t_resp, (
            f"{label} record request_creation_time {rec['request_creation_time']!r} is after its "
            f"response time {rec['time']!r}")
        slack = _dt.timedelta(minutes=5)
        assert run_start - slack <= t_req <= sent_at_end + slack, (
            f"{label} record request_creation_time {rec['request_creation_time']!r} is outside "
            f"this run's request window {run_start.isoformat()}..{sent_at_end.isoformat()}")
        assert re.match(r"^Root=1-[0-9a-f]{8}-[0-9a-f]{24}$", rec["trace_id"]), (
            f"{label} record trace_id is {rec['trace_id']!r}, expected Root=1-<8hex>-<24hex>")
        assert rec["conn_trace_id"].startswith("TID_"), (
            f"{label} record conn_trace_id is {rec['conn_trace_id']!r}, expected TID_<hex>")

    # response_processing_time: there is no target response to process when the target broke —
    # documented as -1 when the target closes the connection — and a real duration otherwise.
    for label, rec in (("ok", ok_rec), ("ua", ua_rec)):
        assert _SECONDS.match(rec["response_processing_time"]), (
            f"{label} record response_processing_time is {rec['response_processing_time']!r}, "
            f"expected seconds with ms precision")
    assert bad_rec["response_processing_time"] == "-1", (
        f"502 record response_processing_time is {bad_rec['response_processing_time']!r}, expected "
        f"'-1' (the target closed the connection without a valid response)")

    # ---- the join across the second hop: what the ALB told the target equals what it logged. ----
    for label, rec, echo in (("ok", ok_rec, ok_echo), ("ua", ua_rec, ua_echo)):
        client_ip, client_port = rec["client:port"].rsplit(":", 1)
        assert client_port.isdigit(), f"{label} record client:port is {rec['client:port']!r}"
        assert echo["xff"] == client_ip, (
            f"{label}: the ALB forwarded X-Forwarded-For {echo['xff']!r} to the target but logged "
            f"client {client_ip!r}")
        assert echo["trace"] == rec["trace_id"], (
            f"{label}: the ALB forwarded X-Amzn-Trace-Id {echo['trace']!r} to the target but logged "
            f"trace_id {rec['trace_id']!r}")
    assert ok_rec["trace_id"] != ua_rec["trace_id"], "two requests were logged with one trace_id"

    # ---- where the record was delivered. -------------------------------------------------------
    key_re = re.compile(
        rf"^AWSLogs/{account}/elasticloadbalancing/{re.escape(ctx.region)}/"
        rf"(\d{{4}})/(\d{{2}})/(\d{{2}})/{account}_elasticloadbalancing_{re.escape(ctx.region)}_"
        rf"{re.escape(lb_id.replace('/', '.'))}_(\d{{8}})T\d{{4}}Z_[0-9.]+_[0-9a-z]+\.log\.gz$")
    for label, recs in found.items():
        key = recs[0][0]
        m = key_re.match(key)
        assert m, f"{label} record was delivered to {key!r}, which is not the documented key form"
        assert "".join(m.groups()[:3]) == m.group(4), (
            f"{key!r}: the <y>/<m>/<d> folder disagrees with the file's end-time date")

    # Reading access logs must not produce access-log records for these paths.
    again = _mine()
    assert {k: len(v) for k, v in again.items()} == {"ok": 1, "ua": 1, "bad": 1}, (
        f"re-reading the bucket changed the record counts: {({k: len(v) for k, v in again.items()})!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
