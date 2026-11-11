"""malformed-lambda-target-response-becomes-a-502-after-the-invocation."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-lambda-target-response-becomes-a-502-after-the-invocation"
GROUP = "cross-service"
SERVICES = ["elbv2", "lambda"]

# ===== helpers =====
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

_CIDR = "10.179.0.0/16"


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
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


#: Not-found codes of the deletes this check's teardowns issue: an already-gone resource is clean.
_GONE_CODES = frozenset({
    "LoadBalancerNotFound", "TargetGroupNotFound", "ListenerNotFound", "RuleNotFound",
    "NoSuchEntity", "ResourceNotFoundException", "NoSuchBucket",
    "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "Gateway.NotAttached",
})


def _safe_cleanup(fn):
    """Teardown wrapper: returns only when the resource is already gone, raises every other failure."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise

    return _wrapped


def _http(ctx, url, *, method="GET", headers=None, timeout=30):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


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
        # _delete_net already retries DependencyViolation while the load balancer's ENIs detach.
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
        # ResourceInUse while a listener or rule being deleted still references the group.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

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
    """The side channel: proves the function RAN even when its response was discarded."""
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
    """Empty the queue and return the message bodies removed. Bounded by a deadline."""
    sqs = ctx.client("sqs")
    drained = []
    empties = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and empties < 2:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=60)
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
    """Receive until `want` messages arrive, or raise. Returns the bodies."""
    sqs = ctx.client("sqs")
    bodies = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(bodies) < want:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=60)
        for m in got.get("Messages") or []:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    assert len(bodies) >= want, (
        f"the target reported {len(bodies)} invocation(s) on the side channel within {timeout_s}s, "
        f"expected {want}; bodies={bodies!r}"
    )
    return bodies


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
                Code={"ZipFile": buf.getvalue()}, Timeout=25, MemorySize=512,
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


def _register_lambda_target(ctx, elb, tg_arn, fn_arn, timeout_s=60.0):
    """RegisterTargets answers AccessDenied until the just-added invoke permission propagates."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return _retry_throttled(lambda: elb.register_targets(
                TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]))
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") != "AccessDenied"
                    or "permission to invoke" not in str(exc) or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _probe(ctx, url):
    try:
        status, _hdrs, body = _http(ctx, url)
    except (urllib.error.URLError, OSError) as exc:
        return (None, f"<transport: {type(exc).__name__}: {exc}>")
    return (status, body.strip())
# ===== end helpers =====

#: One function, five behaviours chosen by the request path. The side-channel message is sent FIRST
#: in every branch — including the branch that raises — so "was the function invoked" is answerable
#: even when the ALB throws the function's answer away. NOTE for a reader grepping for forbidden
#: shapes: the `boto3.client` below is INSIDE the Lambda deployment package source. It runs in AWS
#: Lambda, not in this check process. No client in the CHECK body is built anywhere but
#: ctx.client(...).
_FN_SRC = '''
import json
import os

import boto3

_SQS = boto3.client("sqs")
_QUEUE = os.environ["QUEUE_URL"]


def lambda_handler(event, context):
    path = event.get("path") or ""
    mode = path.rsplit("/", 1)[-1]
    _SQS.send_message(
        QueueUrl=_QUEUE,
        MessageBody=json.dumps({"mode": mode, "request_id": context.aws_request_id}),
    )
    if mode == "nostatus":
        # A response object that omits the one required key.
        return {"statusDescription": "200 OK", "isBase64Encoded": False,
                "headers": {"Content-Type": "text/plain"}, "body": "NO-STATUS-CODE"}
    if mode == "nonjson":
        # Not a JSON object at all.
        return "this is not an ALB response object"
    if mode == "toolarge":
        # Over the documented 1 MB response-body limit, under Lambda's own 6 MB cap.
        return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
                "headers": {"Content-Type": "text/plain"}, "body": "x" * (1536 * 1024)}
    if mode == "raise":
        raise RuntimeError("sim2real deliberate unhandled error")
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "text/plain"}, "body": "TARGET-OK"}
'''


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """When an ALB Lambda target breaks the response contract the client gets 502, and a side channel
    proves the function was invoked each time; the next well-formed response is a 200 again.
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")

    queue_url, queue_arn = _create_queue(ctx)
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(80,))

    role_arn = _create_lambda_role(ctx, queue_arn)
    fn = _create_lambda(ctx, role_arn, _FN_SRC, {"QUEUE_URL": queue_url})

    # Control: the artifact and its side channel work before any load balancer is involved, so a 502
    # below cannot be blamed on a broken function or a broken queue.
    lam.invoke(FunctionName=fn["name"], Payload=json.dumps({"path": "/direct/ok"}).encode())
    direct = _collect(ctx, queue_url, want=1, timeout_s=90)
    assert json.loads(direct[0])["mode"] == "ok", (
        f"side channel carried {direct[0]!r} for a direct invoke, expected mode 'ok'"
    )
    _drain(ctx, queue_url)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    _allow_elb_invoke(ctx, fn["name"], tg_arn)
    _register_lambda_target(ctx, elb, tg_arn, fn["arn"])
    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    slug = _clamp_name(ctx.unique_name("m"), 20)
    base = f"http://{lb['DNSName']}/{slug}"

    # ---- POSITIVE CONTROL through the load balancer. ----------------------------------------
    ok = _poll_until(
        lambda: _probe(ctx, f"{base}/ok"), lambda r: r == (200, "TARGET-OK"),
        timeout_s=420, interval_s=10,
        description="the ALB invoking the Lambda target and returning its well-formed response",
    )
    assert ok == (200, "TARGET-OK"), f"the control request returned {ok!r}, expected (200, 'TARGET-OK')"
    _drain(ctx, queue_url)

    # ---- the four breakages. Exactly one thing differs between them: the path. --------------
    for mode in ("nostatus", "nonjson", "toolarge", "raise"):
        status, body = _probe(ctx, f"{base}/{mode}")
        assert status == 502, (
            f"mode {mode!r}: the load balancer returned HTTP {status} (body {body[:160]!r}), "
            f"expected 502 — the Lambda broke the ALB response contract"
        )
        assert body != "TARGET-OK", (
            f"mode {mode!r}: the 502 body was the well-formed body 'TARGET-OK', which this branch "
            f"never returns"
        )
        assert "NO-STATUS-CODE" not in body and "not an ALB response object" not in body, (
            f"mode {mode!r}: the load balancer proxied the malformed payload through to the client "
            f"({body[:160]!r}); a 502 body must be generated by the load balancer"
        )
        # THE DISCRIMINATOR: the function really ran. A target that was never invoked would also
        # produce a 502, and the two are indistinguishable from the HTTP response alone.
        invoked = _collect(ctx, queue_url, want=1, timeout_s=120)
        modes = {json.loads(b)["mode"] for b in invoked}
        assert modes == {mode}, (
            f"mode {mode!r}: the side channel recorded invocations for {sorted(modes)!r}, expected "
            f"exactly {{{mode!r}}} — so the 502 is the load balancer rejecting the RESPONSE, not "
            f"declining to invoke"
        )
        _drain(ctx, queue_url)

    # ---- restore: a malformed response must not take the target out of service. -------------
    listed = elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert len(listed) == 1 and listed[0]["Target"]["Id"] == fn["arn"], (
        f"after four 502s DescribeTargetHealth reports {listed!r}, expected the single registered "
        f"Lambda {fn['arn']!r} still there"
    )
    again = _probe(ctx, f"{base}/ok")
    assert again == (200, "TARGET-OK"), (
        f"the well-formed request immediately after four malformed ones returned {again!r}, expected "
        f"(200, 'TARGET-OK') — a contract violation must fail that one request, not the target"
    )
    final = _collect(ctx, queue_url, want=1, timeout_s=120)
    assert json.loads(final[0])["mode"] == "ok", (
        f"the side channel recorded {final[0]!r} for the final well-formed request, expected mode 'ok'"
    )


# A load balancer in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries that code in one shared window, then raises naming the ENIs.
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
