"""xsvc-elbv2-3-lambda-invoke-permission-removed-is-denied-with-502-until-regranted."""
from __future__ import annotations

import gzip
import io
import json
import re
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-elbv2-3-lambda-invoke-permission-removed-is-denied-with-502-until-regranted"
GROUP = "cross-service"
SERVICES = ["elbv2", "lambda"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_LOG_DELIVERY_PRINCIPAL = "logdelivery.elasticloadbalancing.amazonaws.com"
_ELB_PRINCIPAL = "elasticloadbalancing.amazonaws.com"
_SID = "sim2real-elbv2-invoke"
_CIDR = "10.183.0.0/16"

#: The documented ALB access-log field order (AWS only appends). Only the fields asserted below
#: matter; the rest are named so a position is never guessed.
_FIELDS = (
    "type", "time", "elb", "client:port", "target:port", "request_processing_time",
    "target_processing_time", "response_processing_time", "elb_status_code",
    "target_status_code", "received_bytes", "sent_bytes", "request", "user_agent", "ssl_cipher",
    "ssl_protocol", "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn",
    "matched_rule_priority", "request_creation_time", "actions_executed", "redirect_url",
    "error_reason",
)
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^ ]+')


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
                        or code in ("NoSuchBucket", "ResourceNotFoundException",
                                    "TargetGroupNotFound", "LoadBalancerNotFound")):
                    return
                last = exc
            time.sleep(interval_s)
        raise RuntimeError(f"{what}: {last!r}")

    return _wrapped


def _http(ctx, url, *, timeout=30):
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, method="GET", headers=route)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _probe(ctx, url):
    try:
        return _http(ctx, url)
    except (urllib.error.URLError, OSError) as exc:
        return (None, f"<transport: {type(exc).__name__}: {exc}>")


def _own_public_vpc(ctx, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _spec(kind):
        return [{"ResourceType": kind, "Tags": list(_TAGS)}]

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(_retrying_delete(f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs ({azs!r}), a load balancer needs {n_subnets}")
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
    for i, az in enumerate(azs[:n_subnets]):
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


def _open_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-lbsg-"), Description="sim2real alb ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_retrying_delete(
        f"security group {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    return sg_id


def _create_load_balancer(ctx, subnets, sg_id):
    elb = ctx.client("elbv2")
    name = _clamp_name(ctx.unique_name("sim2real-xsvc-lb-"))
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
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning", timeout_s=600, interval_s=10,
        description=f"load balancer {name} leaving provisioning")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_bucket(ctx, account, partition):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-logs-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)

    def _empty():
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
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": _LOG_DELIVERY_PRINCIPAL},
                       "Action": "s3:PutObject",
                       "Resource": f"arn:{partition}:s3:::{name}/AWSLogs/{account}/*"}],
    }))
    return name


def _create_queue(ctx):
    """The side channel: proves whether the function RAN, independent of what the ALB answered."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-q-"),
        tags={t["Key"]: t["Value"] for t in _TAGS},
    )["QueueUrl"]
    ctx.on_cleanup(_retrying_delete(f"queue {url}", lambda: sqs.delete_queue(QueueUrl=url),
                                    attempts=3))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_all(ctx, queue_url, *, until, timeout_s):
    """Receive (and delete) until `until(bodies)` holds, then two empty receives in a row."""
    sqs = ctx.client("sqs")
    bodies = []
    deadline = time.monotonic() + timeout_s
    empties = 0
    while time.monotonic() < deadline:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=60)
        msgs = got.get("Messages") or []
        for m in msgs:
            bodies.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if until(bodies):
            empties = 0 if msgs else empties + 1
            if empties >= 2:
                return bodies
    raise AssertionError(
        f"side channel did not reach the expected state within {timeout_s}s; bodies={bodies!r}")


def _create_lambda_role(ctx, queue_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST, Tags=list(_TAGS))["Role"]["Arn"]

    def _drop_role():
        _retrying_delete("role policy", lambda: iam.delete_role_policy(
            RoleName=name, PolicyName="sqs"), attempts=3)()
        _retrying_delete(f"role {name}", lambda: iam.delete_role(RoleName=name), attempts=3)()

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(RoleName=name, PolicyName="sqs", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }))
    return arn


def _reap_log_group_loop(ctx, fn_name):
    """Registered BEFORE create_function so LIFO runs it AFTER the delete. A buffered flush can
    recreate /aws/lambda/<fn> after one delete, so this re-deletes and re-checks a few rounds."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"

    def _reap():
        for _ in range(4):
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            time.sleep(10)
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups") or []
            if not any(g["logGroupName"] == group for g in found):
                return
        raise RuntimeError(f"log group {group} reappeared after 4 delete rounds")

    ctx.on_cleanup(_reap)


def _create_lambda(ctx, role_arn, source, env):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    _reap_log_group_loop(ctx, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=25, MemorySize=256,
                Environment={"Variables": env},
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
        except ClientError as exc:
            # IAM propagation of the freshly created execution role only.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(_try_create, lambda a: a is not None, timeout_s=180, interval_s=5,
                      description=f"lambda {name} accepting the freshly created execution role")
    ctx.on_cleanup(_retrying_delete(f"function {name}",
                                    lambda: lam.delete_function(FunctionName=name), attempts=3))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
                lambda s: s == "Active", timeout_s=180, interval_s=3,
                description=f"lambda {name} reaching State=Active")
    return name, arn


def _parse_record(line):
    raw = _TOKEN.findall(line)
    assert " ".join(raw) == line, f"access-log line is not single-space separated tokens: {line!r}"
    values = [t[1:-1] if len(t) >= 2 and t[0] == '"' and t[-1] == '"' else t for t in raw]
    assert len(values) >= len(_FIELDS), (
        f"access-log line has {len(values)} fields, expected at least {len(_FIELDS)}: {line!r}")
    return dict(zip(_FIELDS, values))


def _log_records(ctx, bucket, account):
    s3 = ctx.client("s3")
    out = []
    kwargs = {"Bucket": bucket, "Prefix": f"AWSLogs/{account}/elasticloadbalancing/"}
    while True:
        listing = s3.list_objects_v2(**kwargs)
        for obj in listing.get("Contents") or []:
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            for line in gzip.decompress(raw).decode("utf-8").splitlines():
                if line.strip():
                    out.append((line, _parse_record(line)))
        if not listing.get("NextContinuationToken"):
            return out
        kwargs["ContinuationToken"] = listing["NextContinuationToken"]

#: Every invocation posts the request path to the side channel BEFORE answering, so "did the ALB
#: invoke the function" is answerable for every request regardless of the HTTP status it produced.
#: NOTE: the boto3.client below is INSIDE the Lambda deployment package; it runs in AWS Lambda, not
#: in this check process.
_FN_SRC = '''
import json
import os

import boto3

_SQS = boto3.client("sqs")
_QUEUE = os.environ["QUEUE_URL"]


def lambda_handler(event, context):
    path = event.get("path") or ""
    _SQS.send_message(QueueUrl=_QUEUE, MessageBody=json.dumps({"path": path}))
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "text/plain"}, "body": "TARGET-OK " + path}
'''


# timing:real-time — buffer: 186 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """Removing the ALB's Lambda invoke permission from a registered target makes every request a
    502 with the function never invoked and the access log reading LambdaAccessDenied; re-adding it
    restores 200 with no re-registration, so the permission is re-checked on every invoke.
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")
    ident = ctx.client("sts").get_caller_identity()
    account, partition = ident["Account"], ident["Arn"].split(":")[1]

    queue_url, queue_arn = _create_queue(ctx)
    bucket = _create_bucket(ctx, account, partition)
    vpc_id, subnets = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id)
    role_arn = _create_lambda_role(ctx, queue_arn)
    fn_name, fn_arn = _create_lambda(ctx, role_arn, _FN_SRC, {"QUEUE_URL": queue_url})

    lb = _create_load_balancer(ctx, subnets, sg_id)
    lb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]

    def _enable_logs():
        try:
            return elb.modify_load_balancer_attributes(LoadBalancerArn=lb_arn, Attributes=[
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": bucket}])["Attributes"]
        except ClientError as exc:
            # Bucket-policy propagation only; any other refusal fails immediately.
            if exc.response.get("Error", {}).get("Code") == "InvalidConfigurationRequest":
                return None
            raise

    _poll_until(_enable_logs, lambda a: a is not None, timeout_s=180, interval_s=10,
                description="access logging accepted once the bucket policy grants log delivery")
    ctx.on_cleanup(_retrying_delete("disable access logs", lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=[{"Key": "access_logs.s3.enabled", "Value": "false"}]),
        attempts=3))

    tg = _retry_throttled(lambda: elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-xsvc-tg-")), TargetType="lambda",
        Tags=list(_TAGS)))["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(_retrying_delete(f"target group {tg_arn}",
                                    lambda: elb.delete_target_group(TargetGroupArn=tg_arn),
                                    attempts=15, interval_s=4))

    def _grant():
        lam.add_permission(FunctionName=fn_name, StatementId=_SID, Action="lambda:InvokeFunction",
                           Principal=_ELB_PRINCIPAL, SourceArn=tg_arn)

    _grant()
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]))
    ctx.on_cleanup(_retrying_delete("deregister lambda", lambda: elb.deregister_targets(
        TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]), attempts=3))
    listener_arn = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}]))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_retrying_delete("listener", lambda: elb.delete_listener(ListenerArn=listener_arn),
                                    attempts=3))

    marker = _clamp_name(ctx.unique_name("p"), 24)
    base = f"http://{dns}"

    # ---- POSITIVE CONTROL: granted, the ALB invokes the function and returns its body. --------
    _poll_until(lambda: _probe(ctx, f"{base}/{marker}/warm"), lambda r: r[0] == 200,
                timeout_s=420, interval_s=10, description="the ALB serving the Lambda target")
    granted_path = f"/{marker}/granted"
    granted = _probe(ctx, base + granted_path)
    assert granted == (200, f"TARGET-OK {granted_path}"), (
        f"with the invoke permission in place the ALB returned {granted!r}, expected "
        f"(200, 'TARGET-OK {granted_path}')")
    _receive_all(ctx, queue_url, until=lambda b: any(x["path"] == granted_path for x in b),
                 timeout_s=120)

    # ---- BREAK ONE THING: remove the statement. The target stays registered. ------------------
    lam.remove_permission(FunctionName=fn_name, StatementId=_SID)
    policy_gone = _poll_until(
        lambda: _policy_sids(lam, fn_name), lambda s: _SID not in s, timeout_s=60, interval_s=3,
        description="the removed Sid disappearing from GetPolicy")
    assert _SID not in policy_gone, f"GetPolicy still lists {_SID!r}: {policy_gone!r}"

    counter = {"n": 0}

    def _denied_probe():
        counter["n"] += 1
        path = f"/{marker}/denied-{counter['n']}"
        return path, _probe(ctx, base + path)

    first = _poll_until(_denied_probe, lambda r: r[1][0] == 502, timeout_s=180, interval_s=5,
                        description="the ALB answering 502 once the invoke permission is removed")
    denied = [first]
    for _ in range(3):
        denied.append(_denied_probe())
    for path, (status, body) in denied:
        assert status == 502, (
            f"{path}: with the permission removed the ALB returned HTTP {status} body "
            f"{body[:160]!r}, expected 502 on every request once the removal took effect")
        assert "TARGET-OK" not in body, (
            f"{path}: the 502 body {body[:160]!r} contains the function's own body — a denied "
            f"invoke must never reach the function")
    denied_paths = {p for p, _ in denied}

    targets = elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert [t["Target"]["Id"] for t in targets] == [fn_arn], (
        f"after removing the permission DescribeTargetHealth lists {targets!r}, expected the "
        f"Lambda {fn_arn!r} still registered — the denial is per-invoke, not a deregistration")

    # ---- RESTORE: re-add the same statement; no re-registration. ------------------------------
    _grant()
    _poll_until(lambda: _probe(ctx, f"{base}/{marker}/regrant-wait"), lambda r: r[0] == 200,
                timeout_s=180, interval_s=5,
                description="the ALB serving 200 again after the invoke permission is re-added")
    restored_path = f"/{marker}/restored"
    restored = _probe(ctx, base + restored_path)
    assert restored == (200, f"TARGET-OK {restored_path}"), (
        f"after re-adding the permission the ALB returned {restored!r}, expected "
        f"(200, 'TARGET-OK {restored_path}')")

    # ---- the side channel: the restored request arrived, and NO denied request ever ran. -----
    bodies = _receive_all(ctx, queue_url,
                          until=lambda b: any(x["path"] == restored_path for x in b),
                          timeout_s=120)
    ran = {b["path"] for b in bodies}
    assert not (ran & denied_paths), (
        f"the function recorded invocations for {sorted(ran & denied_paths)!r}, which the ALB "
        f"answered 502 — a denied invoke must not reach the function")

    # ---- the access log: the 502s carry LambdaAccessDenied; the controls carry none. ----------
    probe_paths = {granted_path: "granted", restored_path: "restored", denied[-1][0]: "denied"}

    def _mine():
        found = {}
        for line, rec in _log_records(ctx, bucket, account):
            parts = rec["request"].split(" ")
            path = parts[1].split(f"{dns}:80", 1)[-1] if len(parts) == 3 else None
            if path in probe_paths:
                found.setdefault(probe_paths[path], []).append((line, rec))
        return found

    found = _poll_until(_mine, lambda f: len(f) == 3, timeout_s=900, interval_s=30,
                        description=f"access-log records for granted/denied/restored in s3://{bucket}")
    for label, recs in found.items():
        print(f"[record:{label}] {recs[0][0]}")
        assert len(recs) == 1, f"{label!r} request produced {len(recs)} records: {recs!r}"
    bad = found["denied"][0][1]
    assert (bad["elb_status_code"], bad["target_status_code"], bad["error_reason"]) == (
            "502", "-", "LambdaAccessDenied"), (
        f"the denied request was logged elb/target/error_reason "
        f"{bad['elb_status_code']!r}/{bad['target_status_code']!r}/{bad['error_reason']!r}, "
        f"expected '502'/'-'/'LambdaAccessDenied'; record {found['denied'][0][0]!r}")
    assert bad["target_group_arn"] == tg_arn, (
        f"the denied record names target group {bad['target_group_arn']!r}, expected {tg_arn!r}")
    for label in ("granted", "restored"):
        rec = found[label][0][1]
        assert (rec["elb_status_code"], rec["target_status_code"], rec["error_reason"]) == (
                "200", "200", "-"), (
            f"the {label} request was logged elb/target/error_reason "
            f"{rec['elb_status_code']!r}/{rec['target_status_code']!r}/{rec['error_reason']!r}, "
            f"expected '200'/'200'/'-'")


def _policy_sids(lam, fn_name):
    try:
        doc = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return set()
        raise
    return {s.get("Sid") for s in doc.get("Statement") or []}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
