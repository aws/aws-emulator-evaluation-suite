"""desync-mitigation-strictest-blocks-ambiguous-framing-before-the-target."""
from __future__ import annotations

# The load balancer also closes the client connection on a blocked request; that is not asserted
# because every request here carries `Connection: close`, so a close would prove nothing.

import io
import json
import socket
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "desync-mitigation-strictest-blocks-ambiguous-framing-before-the-target"
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

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_CIDR = "10.172.0.0/16"


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


_GONE_CODES = frozenset(
    {"Gateway.NotAttached", "NoSuchEntity", "AWS.SimpleQueueService.NonExistentQueue"})


def _gone(exc):
    """A teardown delete whose resource is already gone is done."""
    code = exc.response.get("Error", {}).get("Code", "")
    return code.endswith(("NotFound", "NotFoundException")) or code in _GONE_CODES


def _safe_cleanup(fn):
    """Teardown: a resource that is already gone is done; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if not _gone(exc):
                raise

    return _wrapped


def _own_public_vpc(ctx, cidr=_CIDR, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    ]
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets} for a load balancer"
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


def _open_sg(ctx, vpc_id, ports=(80,)):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _safe_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))()

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for p in ports
        ],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(Name=name, Subnets=subnet_ids, Type="application",
                  Scheme="internal", Tags=list(_TAGS))
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
    assert lb["State"]["Code"] == "active", (
        f"load balancer state {lb['State']!r}, expected State.Code == 'active'"
    )
    return lb


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


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_listener(ListenerArn=arn)))
    return listener


def _create_queue(ctx):
    """The side channel: exact invocation counts the ALB API will not report."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        tags={t["Key"]: t["Value"] for t in _TAGS},
    )["QueueUrl"]
    ctx.on_cleanup(_safe_cleanup(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _drain(ctx, queue_url, *, settle_s=8):
    """Empty the queue and return the messages removed. Bounded: stops on two empty receives."""
    sqs = ctx.client("sqs")
    drained = []
    empties = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and empties < 2:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
            VisibilityTimeout=60)
        msgs = got.get("Messages") or []
        if not msgs:
            empties += 1
            continue
        empties = 0
        for m in msgs:
            drained.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    if settle_s:
        # SQS receives are a sample, not a snapshot: one more long-poll receive of up to 8s picks
        # up a message that was in flight during the last receive, so it is attributed to THIS
        # leg instead of the NEXT one. The receive returns as soon as a message arrives.
        while time.monotonic() < deadline + 8:
            got = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(settle_s, 8),
                VisibilityTimeout=60)
            msgs = got.get("Messages") or []
            if not msgs:
                break
            for m in msgs:
                drained.append(m["Body"])
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return drained


def _collect(ctx, queue_url, *, want, timeout_s):
    """Receive until `want` messages have arrived, or raise. Returns (bodies, elapsed_seconds)."""
    sqs = ctx.client("sqs")
    bodies = []
    start = time.monotonic()
    deadline = start + timeout_s
    while time.monotonic() < deadline and len(bodies) < want:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=60)
        for m in got.get("Messages") or []:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    elapsed = time.monotonic() - start
    assert len(bodies) >= want, (
        f"the target reported {len(bodies)} invocation(s) on the side channel within {timeout_s}s, "
        f"expected {want}; bodies={bodies!r}"
    )
    return bodies, elapsed


def _visible_count(ctx, queue_url):
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (int(attrs["ApproximateNumberOfMessages"]),
            int(attrs["ApproximateNumberOfMessagesNotVisible"]))


def _create_lambda_role(ctx, queue_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["Role"]["Arn"]

    def _drop_role():
        _safe_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sqs"))()
        _safe_cleanup(lambda: iam.delete_role(RoleName=name))()

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(
        RoleName=name, PolicyName="sqs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage",
                           "Resource": queue_arn}],
        }),
    )
    return arn


def _create_lambda(ctx, role_arn, source, env):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=20, MemorySize=256,
                Environment={"Variables": env},
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(
        _try_create, lambda a: a is not None, timeout_s=180, interval_s=5,
        description=f"lambda {name} accepting the freshly created execution role",
    )
    ctx.on_cleanup(_safe_cleanup(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", timeout_s=180, interval_s=3,
        description=f"lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": arn}


def _allow_elb_invoke(ctx, fn_name, tg_arn):
    lam = ctx.client("lambda")
    try:
        lam.add_permission(
            FunctionName=fn_name, StatementId="elbv2-invoke",
            Action="lambda:InvokeFunction",
            Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


def _register_targets_once_authorized(ctx, tg_arn, fn_arn, timeout_s=60, interval_s=5):
    """RegisterTargets after `_allow_elb_invoke`: the grant applies asynchronously (up to tens of
    seconds), so that specific rejection is retried, bounded; anything else raises immediately."""
    elb = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return _retry_throttled(lambda: elb.register_targets(
                TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last = exc
            time.sleep(interval_s)
    raise last


def _raw_request(ctx, host, request_bytes, *, port=80, timeout=20):
    """Send handcrafted HTTP/1.1 bytes and return (status_line, body, closed_by_peer). A raw socket,
    because http.client normalises the framing headers this check is about."""
    _t = urllib.parse.urlsplit(ctx.endpoint_url(f"http://{host}"))
    with socket.create_connection((_t.hostname, _t.port or port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request_bytes)
        chunks = []
        closed = False
        while True:
            try:
                part = sock.recv(65536)
            except (TimeoutError, socket.timeout, OSError):
                break
            if not part:
                closed = True
                break
            chunks.append(part)
            if len(b"".join(chunks)) > 262144:
                break
    raw = b"".join(chunks)
    assert raw, f"the load balancer at {host}:{port} returned zero bytes for a raw HTTP request"
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    return status_line, body.decode("utf-8", "replace"), closed


_CONNECT_NOT_READY = (ConnectionRefusedError, ConnectionResetError, TimeoutError,
                       socket.timeout, socket.gaierror)


def _connect_tolerant(probe):
    """Wrap a `_raw_request` probe for `_poll_until`: an 'active' load balancer's nodes can still
    refuse TCP briefly, so ECONNREFUSED becomes a sentinel that keeps polling. Callers still assert
    the exact status line once polling stops."""
    def _wrapped():
        try:
            return probe()
        except _CONNECT_NOT_READY as exc:
            return (f"<connect-not-ready: {exc}>", "", False)

    return _wrapped


def _set_desync_mode(ctx, lb_arn, mode):
    """Set the mode and assert the control plane reports it back before touching the data plane."""
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "routing.http.desync_mitigation_mode", "Value": mode}],
    ))
    attrs = {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn)["Attributes"]}
    got = attrs.get("routing.http.desync_mitigation_mode")
    assert got == mode, (
        f"DescribeLoadBalancerAttributes reports routing.http.desync_mitigation_mode={got!r} after "
        f"setting it to {mode!r}"
    )

#: Every invocation is announced on the side channel BEFORE the response is built, so a target that
#: was reached is countable even if its response is discarded.
#: The `boto3.client` below runs inside the Lambda deployment package, not in this check process.
_FN_SRC = '''
import json
import os
import urllib.parse
import urllib.request

import boto3

_SQS = boto3.client("sqs")
_QUEUE = os.environ["QUEUE_URL"]


def lambda_handler(event, context):
    _SQS.send_message(
        QueueUrl=_QUEUE,
        MessageBody=json.dumps({
            "path": event.get("path"),
            "method": event.get("httpMethod"),
            "request_id": context.aws_request_id,
        }),
    )
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "text/plain"}, "body": "TARGET-REACHED"}
'''


def _compliant(host, path):
    body = b"sim2real"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1") + body


def _ambiguous(host, path):
    """The canonical request-smuggling vector: two mutually exclusive framing headers."""
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: 8\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n\r\n"
    ).encode("latin-1")


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With desync_mitigation_mode=strictest the ALB answers an ambiguously framed request with 400
    and never invokes the target, while the identical bytes under `monitor` reach it: exact
    invocation counts on an SQS side channel, with a compliant POST forwarded in both modes.
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")

    queue_url, queue_arn = _create_queue(ctx)
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(80,))

    role_arn = _create_lambda_role(ctx, queue_arn)
    fn = _create_lambda(ctx, role_arn, _FN_SRC, {"QUEUE_URL": queue_url})

    # Control: the artifact and its side channel both work before any load balancer is involved.
    lam.invoke(FunctionName=fn["name"],
               Payload=json.dumps({"path": "/direct", "httpMethod": "POST"}).encode())
    direct, _ = _collect(ctx, queue_url, want=1, timeout_s=60)
    assert json.loads(direct[0])["path"] == "/direct", (
        f"side channel carried {direct[0]!r} for a direct invoke, expected path '/direct'"
    )

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, lb_arn)

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    _allow_elb_invoke(ctx, fn["name"], tg_arn)
    _register_targets_once_authorized(ctx, tg_arn, fn["arn"])
    _create_listener(
        ctx, lb_arn, Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    host = lb["DNSName"]
    path = f"/{_clamp_name(ctx.unique_name('probe-'), 24)}"

    # ---- leg 1: mode=monitor. Both request shapes reach the target. -----------------------
    _set_desync_mode(ctx, lb_arn, "monitor")
    status, body, _closed = _poll_until(
        _connect_tolerant(lambda: _raw_request(ctx, host, _compliant(host, path))),
        lambda r: r[0].endswith("200 OK") and r[1].strip() == "TARGET-REACHED",
        timeout_s=420, interval_s=10,
        description="the load balancer forwarding a compliant raw POST to the Lambda target",
    )
    assert status.endswith("200 OK"), f"compliant POST under monitor: status line {status!r}"
    _drain(ctx, queue_url)

    amb_status, amb_body, _amb_closed = _poll_until(
        _connect_tolerant(lambda: _raw_request(ctx, host, _ambiguous(host, path))),
        lambda r: r[0].endswith("200 OK"),
        timeout_s=300, interval_s=10,
        description="the load balancer FORWARDING an ambiguously framed POST while the desync "
                    "mitigation mode is `monitor`",
    )
    assert amb_body.strip() == "TARGET-REACHED", (
        f"under monitor the ambiguous POST returned status {amb_status!r} body "
        f"{amb_body.strip()[:80]!r}, expected the target's own body 'TARGET-REACHED'"
    )
    monitor_msgs, control_latency = _collect(ctx, queue_url, want=1, timeout_s=90)
    assert json.loads(monitor_msgs[0])["path"] == path, (
        f"side channel carried {monitor_msgs[0]!r}, expected path {path!r}"
    )
    _drain(ctx, queue_url)

    # ---- leg 2: break EXACTLY one thing — the mode. ---------------------------------------
    _set_desync_mode(ctx, lb_arn, "strictest")
    blocked = _poll_until(
        _connect_tolerant(lambda: _raw_request(ctx, host, _ambiguous(host, path))),
        lambda r: not r[0].endswith("200 OK"),
        timeout_s=300, interval_s=10,
        description="the ambiguously framed POST stopping being forwarded after the desync "
                    "mitigation mode was set to `strictest`",
    )
    # Anything the convergence poll leaked onto the side channel belongs to the transition, not to
    # the assertion below.
    _drain(ctx, queue_url)

    assert blocked[0] == "HTTP/1.1 400 Bad Request", (
        f"under strictest the ambiguously framed POST got status line {blocked[0]!r}, expected "
        f"exactly 'HTTP/1.1 400 Bad Request'"
    )

    # POSITIVE CONTROL IN THE SAME INSTANT: strictest does not block everything.
    ok_status, ok_body, _ = _raw_request(ctx, host, _compliant(host, path))
    assert ok_status.endswith("200 OK") and ok_body.strip() == "TARGET-REACHED", (
        f"under strictest the COMPLIANT POST got {(ok_status, ok_body.strip()[:60])!r}, expected "
        f"200/TARGET-REACHED — without this the 400 above is indistinguishable from 'strictest "
        f"rejects every request'"
    )
    control_msgs, control_latency = _collect(ctx, queue_url, want=1, timeout_s=90)
    assert len(control_msgs) == 1, (
        f"the compliant POST produced {len(control_msgs)} side-channel messages, expected exactly 1"
    )
    _drain(ctx, queue_url)

    # EFFECT ABSENT, bounded by the control latency just measured on the same wiring.
    for i in range(3):
        st, _b, _c = _raw_request(ctx, host, _ambiguous(host, path))
        assert st == "HTTP/1.1 400 Bad Request", (
            f"ambiguous POST {i + 1}/3 under strictest got status line {st!r}, expected "
            f"'HTTP/1.1 400 Bad Request'"
        )
    # The window is CALIBRATED, not guessed: it is 3x the latency the compliant POST needed to show
    # up on this same queue moments ago, floored at 15s. Absence is re-checked throughout rather
    # than once at the end, so a late arrival cannot slip in between two observations.
    hold_s = max(15.0, 3.0 * control_latency)
    hold_deadline = time.monotonic() + hold_s
    leaked = []
    while time.monotonic() < hold_deadline:
        leaked.extend(_drain(ctx, queue_url, settle_s=0))
        if leaked:
            break
    assert leaked == [], (
        f"the target was invoked {len(leaked)} time(s) by requests the load balancer answered with "
        f"400: {leaked!r}; expected zero, held for {hold_s:.0f}s = 3x the "
        f"{control_latency:.1f}s latency the compliant POST needed on this same wiring"
    )
    visible, in_flight = _visible_count(ctx, queue_url)
    assert (visible, in_flight) == (0, 0), (
        f"a second independent observable disagrees: ApproximateNumberOfMessages={visible}, "
        f"ApproximateNumberOfMessagesNotVisible={in_flight}, expected (0, 0)"
    )

    # ---- leg 3: restore the ONE thing that changed; the identical call succeeds. -----------
    _set_desync_mode(ctx, lb_arn, "monitor")
    restored = _poll_until(
        _connect_tolerant(lambda: _raw_request(ctx, host, _ambiguous(host, path))),
        lambda r: r[0].endswith("200 OK") and r[1].strip() == "TARGET-REACHED",
        timeout_s=300, interval_s=10,
        description="the identical ambiguously framed POST being forwarded again once the desync "
                    "mitigation mode is back to `monitor`",
    )
    assert restored[1].strip() == "TARGET-REACHED", (
        f"after restoring mode=monitor the ambiguous POST returned {restored!r}, expected the "
        f"target's own body 'TARGET-REACHED' — so the refusal was attributable to the mode alone"
    )
    final_msgs, _ = _collect(ctx, queue_url, want=1, timeout_s=90)
    assert final_msgs, "no side-channel invocation after the mode was restored to monitor"


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise naming the ENIs
# still attached when the window ends. The window is shared by all of one check's network deletes.
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
