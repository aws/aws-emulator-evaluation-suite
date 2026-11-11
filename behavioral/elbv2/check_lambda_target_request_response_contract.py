"""lambda-target-request-response-contract."""
from __future__ import annotations

import base64
import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-request-response-contract"
GROUP = 'data-plane'
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

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


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


def _register_lambda_target_awaiting_invoke_permission(elb, tg_arn, target_id, timeout_s=60):
    """RegisterTargets checks lambda:InvokeFunction up front, and the resource
    policy just granted by add_permission propagates with a short lag."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "AccessDenied" and "does not have permission to invoke" in str(exc):
                last = exc
                time.sleep(3)
                continue
            raise
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


def _http(ctx, url, *, method="GET", headers=None, timeout=25):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _own_vpc_and_subnets(ctx, num_subnets=2):
    """A routable VPC and public subnets this check creates for the internet-facing ALB."""
    return _own_public_vpc(ctx, n_subnets=num_subnets)


def _delete_retrying(fn, *, gone, busy=(), timeout_s=0):
    """Teardown delete: done on success or a `gone` code; retries a `busy` code every 2 s while a
    dependency is released, up to timeout_s; raises every other failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _open_http_sg(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # A deleting load balancer's ENIs hold the group briefly: retry only DependencyViolation.
        _delete_retrying(lambda: ec2.delete_security_group(GroupId=sg_id), gone={"InvalidGroup.NotFound"},
                         busy={"DependencyViolation"}, timeout_s=180)

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()],
        }],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
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
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A listener or deleting load balancer holds the group briefly: retry only ResourceInUse.
        _delete_retrying(lambda: elb.delete_target_group(TargetGroupArn=arn), gone={"TargetGroupNotFound"},
                         busy={"ResourceInUse"}, timeout_s=60)

    ctx.on_cleanup(_drop_tg)
    return tg


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["Role"]["Arn"]

    def _drop_role():
        try:
            for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_role)
    return arn


def _create_lambda(ctx, role_arn, source):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    deadline = time.monotonic() + 90
    arn = None
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=20, MemorySize=128,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidParameterValueException",) or "cannot be assumed" in str(exc):
                last = exc
                time.sleep(4)
                continue
            raise
    assert arn is not None, f"lambda {name} not created: {last!r}"
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", timeout_s=120, interval_s=3,
        description=f"lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": arn}


def _try_json(ctx, url, *, headers=None, seen=None):
    """One request: (status, headers, event) for a 2xx JSON echo, else None."""
    seen = seen if seen is not None else []
    try:
        status, hdrs, body = _http(ctx, url, headers=headers)
    except (urllib.error.URLError, OSError) as exc:
        seen.append(f"<transport: {exc}>")
        return None
    seen.append(f"{status}:{body[:60]}")
    if status // 100 != 2:
        return None
    try:
        return (status, hdrs, json.loads(body))
    except ValueError:
        return None


def _wait_for_json(ctx, url, *, headers=None, timeout_s=300, description=""):
    """Poll until the ALB returns a 2xx whose body parses as the handler's JSON echo."""
    seen = []
    return _poll_until(
        lambda: _try_json(ctx, url, headers=headers, seen=seen), lambda r: r is not None,
        timeout_s=timeout_s, interval_s=5,
        description=description or f"ALB returning the Lambda target's JSON echo at {url} "
                                  f"(observed: {seen[-6:]})",
    )
# ===== end helpers =====

_FN_SRC = '''
import base64
import json


def lambda_handler(event, context):
    if event.get("path") == "/b64":
        return {
            "statusCode": 200,
            "statusDescription": "200 OK",
            "isBase64Encoded": True,
            "headers": {"Content-Type": "text/plain"},
            "body": base64.b64encode(b"sim2real-binary-ok").decode(),
        }
    return {
        "statusCode": 201,
        "statusDescription": "201 Created",
        "isBase64Encoded": False,
        "headers": {"Content-Type": "application/json", "X-Sim2Real-Echo": "yes"},
        "body": json.dumps(event),
    }
'''


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ALB invokes its Lambda target with the ALB event shape (requestContext.elb, method, path,
    query, headers), maps the returned statusCode/headers/isBase64Encoded onto the HTTP response,
    and lambda.multi_value_headers.enabled switches the event to multi-value keys."""
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")
    vpc_id, subnet_ids = _own_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda(ctx, role_arn, _FN_SRC)

    # Control: the artifact itself works, so an ALB routing failure is unambiguous.
    direct = json.loads(lam.invoke(
        FunctionName=fn["name"], Payload=json.dumps({"path": "/direct"}).encode(),
    )["Payload"].read())
    assert direct.get("statusCode") == 201, f"direct invoke returned {direct!r}"

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    lam.add_permission(
        FunctionName=fn["name"], StatementId="elbv2-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn,
    )
    _register_lambda_target_awaiting_invoke_permission(elb, tg_arn, fn["arn"])
    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    base = f"http://{lb['DNSName']}"

    # 1. The request reaches the Lambda and the ALB event shape is correct.
    status, hdrs, event = _wait_for_json(
        ctx, f"{base}/echo/path?k=v", headers={"X-Sim2Real": "req-1"},
        description="ALB invoking the Lambda target and returning its echo",
    )
    assert status == 201, f"Lambda statusCode 201 not surfaced as the HTTP status: {status}"
    assert hdrs.get("X-Sim2Real-Echo") == "yes", (
        f"Lambda response header not surfaced; headers={dict(hdrs)!r}"
    )
    assert hdrs.get("Content-Type") == "application/json", dict(hdrs)
    assert event.get("httpMethod") == "GET", event
    assert event.get("path") == "/echo/path", event
    assert event.get("queryStringParameters") == {"k": "v"}, event
    assert event.get("isBase64Encoded") is False, event
    elb_ctx = (event.get("requestContext") or {}).get("elb") or {}
    assert elb_ctx.get("targetGroupArn") == tg_arn, (
        f"requestContext.elb.targetGroupArn missing/wrong: {event.get('requestContext')!r}"
    )
    ev_headers = event.get("headers") or {}
    assert ev_headers.get("x-sim2real") == "req-1", (
        f"request header not lower-cased into event.headers: {sorted(ev_headers)!r}"
    )
    assert "multiValueQueryStringParameters" not in event, (
        "multi-value keys present while lambda.multi_value_headers.enabled is off"
    )

    # 2. isBase64Encoded=True bodies are base64-DECODED onto the wire.
    b64_status, _b64_hdrs, b64_body = _http(ctx, f"{base}/b64")
    assert b64_status == 200, b64_status
    assert b64_body == "sim2real-binary-ok", (
        f"isBase64Encoded body not decoded: {b64_body!r} "
        f"(raw base64 would be {base64.b64encode(b'sim2real-binary-ok').decode()!r})"
    )

    # 3. lambda.multi_value_headers.enabled switches the event to the multi-value shape.
    elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "lambda.multi_value_headers.enabled", "Value": "true"}],
    )
    attrs = {
        a["Key"]: a["Value"]
        for a in elb.describe_target_group_attributes(TargetGroupArn=tg_arn)["Attributes"]
    }
    assert attrs.get("lambda.multi_value_headers.enabled") == "true", attrs

    def _multi():
        got = _try_json(ctx, f"{base}/echo/path?k=v1&k=v2", headers={"X-Sim2Real": "req-2"})
        return got[2] if got else None

    event2 = _poll_until(
        _multi, lambda ev: ev is not None and "multiValueQueryStringParameters" in ev,
        timeout_s=240, interval_s=10,
        description="event switching to the multi-value key shape after enabling the attribute",
    )
    assert event2["multiValueQueryStringParameters"] == {"k": ["v1", "v2"]}, event2
    assert "multiValueHeaders" in event2, sorted(event2)
    assert event2["multiValueHeaders"].get("x-sim2real") == ["req-2"], event2["multiValueHeaders"]
    assert "queryStringParameters" not in event2, (
        "single-value queryStringParameters still present with multi-value headers enabled"
    )
    assert "headers" not in event2, (
        "single-value headers still present with multi-value headers enabled"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

# ===== own network (self-contained) =====

_NET_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


# Not-found codes a teardown treats as already deleted; every other error raises.
_GONE = frozenset({
    "TargetGroupNotFound", "InvalidTarget", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound",
})


def _net_safe_cleanup(fn):
    """Wrap one teardown call: a resource already gone is fine; any other error raises."""
    from botocore.exceptions import ClientError as _ClientError

    def _wrapped():
        try:
            fn()
        except _ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                raise

    return _wrapped


def _own_public_vpc(ctx, cidr="10.173.0.0/16", n_subnets=2):
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
    assert len(azs) >= n_subnets, f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets}"

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
# DependencyViolation inside one shared window, and raise a final failure naming the ENIs.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict.
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
