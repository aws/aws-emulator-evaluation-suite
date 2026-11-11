"""listener-rule-priority-decides-which-rule-serves-the-request."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-rule-priority-decides-which-rule-serves-the-request"
GROUP = 'ordering'
SERVICES = ['elbv2']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0

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


def _poll_until(probe, predicate, *, timeout_s=POLL_BUDGET_S, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(url, *, method="GET", headers=None, timeout=20, verify=True):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context(verify)))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


# Not-found codes a teardown treats as already deleted; every other error raises.
_GONE = frozenset({
    "ListenerNotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound",
})


def _safe(fn):
    """Wrap one teardown call: a resource already gone is fine; any other error raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                raise
    return _wrapped


def _own_vpc_and_subnets(ctx, num_subnets=2):
    """A routable VPC built by the check, not an ambient default: a freshly
    provisioned account may have no default VPC at all."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    # Opted-in Local Zones also list as available, and one ALB cannot mix them with AZs.
    azs = sorted(
        a["ZoneName"] for a in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )[:num_subnets]
    if len(azs) < num_subnets:
        raise AssertionError(f"region exposes {len(azs)} available AZs, need {num_subnets}")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.93.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(_safe(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        subnet_ids.append(subnet_id)

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": list(_TAGS)}],
    )["InternetGateway"]["InternetGatewayId"]

    def _teardown_igw():
        _safe(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _safe(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_teardown_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": list(_TAGS)}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for subnet_id in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(_safe(lambda aid=assoc_id: ec2.disassociate_route_table(AssociationId=aid)))

    return vpc_id, subnet_ids


def _open_http_sg(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # The ALB's ENIs hold this group: _delete_net waits them out and retries DependencyViolation.
        try:
            _delete_net(ec2, "delete_security_group", GroupId=sg_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidGroup.NotFound":
                raise

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


def _wait_for_lb_active(ctx, lb_arn, timeout_s=POLL_BUDGET_S):
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
    ctx.on_cleanup(_safe(lambda: elb.delete_listener(ListenerArn=arn)))
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
            if exc.response["Error"]["Code"] != "RuleNotFound":
                raise
            return

    ctx.on_cleanup(_drop_rule)
    return rule


def _wait_for_body(url, expected, *, timeout_s=POLL_BUDGET_S, headers=None, verify=True):
    """Poll until the load balancer serves exactly `expected` (body, or (status, body)).

    A configuration change reaches the data plane asynchronously, so every leg polls the
    request rather than asserting once; the poll is BOUNDED so a load balancer that never
    changes behaviour fails instead of hanging.
    """
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(url, headers=headers, verify=verify)
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

    try:
        return _poll_until(
            probe, matches, timeout_s=timeout_s, interval_s=5,
            description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
        )
    except AssertionError as exc:
        if seen and all(s.startswith("<transport:") for s in seen):
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: nothing answered at the ALB listener {url} within "
                f"{timeout_s}s, so listener-rule evaluation could not be observed at all: {seen[-1]}"
            ) from exc
        raise
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Listener-rule priority, not creation order, decides which of two matching rules serves a
    request: swapping priorities flips the served body, a priority-1 rule beats both, and deleting
    it falls back to the priority-10 rule."""
    elb = ctx.client("elbv2")
    vpc_id, subnet_ids = _own_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=_fixed("DEFAULT"),
    )
    la = listener["ListenerArn"]

    # The published DNSName is reached only through the target's mapping of it; the listener is
    # plain HTTP on port 80, so the scheme is explicit, and the Host header names the ALB.
    url = f"{ctx.endpoint_url('http://' + lb['DNSName'])}/pick/one"
    host = {"Host": lb["DNSName"]}
    verify = ctx.http_verify
    # Readiness is observable: the listener's own default action being served.
    _wait_for_body(url, "DEFAULT", headers=host, verify=verify)

    rule_a = _create_rule(ctx, la, 10, ["/pick*"], "RULE-A")
    rule_b = _create_rule(ctx, la, 20, ["/pick*"], "RULE-B")

    statuses = []

    status_initial, body_initial = _wait_for_body(url, "RULE-A", headers=host, verify=verify)
    statuses.append(status_initial)
    assert body_initial.strip() == "RULE-A", (
        f"with A at priority 10 and B at 20 the load balancer served "
        f"{body_initial.strip()!r}, expected RULE-A"
    )

    # A single SetRulePriorities call swaps them atomically; two calls would collide on the
    # uniqueness constraint half way through.
    _retry_throttled(lambda: elb.set_rule_priorities(RulePriorities=[
        {"RuleArn": rule_a["RuleArn"], "Priority": 20},
        {"RuleArn": rule_b["RuleArn"], "Priority": 10},
    ]))
    status_swapped, body_swapped = _wait_for_body(url, "RULE-B", headers=host, verify=verify)
    statuses.append(status_swapped)
    assert body_swapped.strip() == "RULE-B", (
        f"after swapping priorities the load balancer served {body_swapped.strip()!r}, "
        f"expected RULE-B"
    )

    rule_c = _create_rule(ctx, la, 1, ["/pick*"], "RULE-C")
    status_with_c, body_with_c = _wait_for_body(url, "RULE-C", headers=host, verify=verify)
    statuses.append(status_with_c)
    assert body_with_c.strip() == "RULE-C", (
        f"a rule at priority 1 did not win: served {body_with_c.strip()!r}, expected RULE-C"
    )

    _retry_throttled(lambda: elb.delete_rule(RuleArn=rule_c["RuleArn"]))
    status_after_c, body_after_c = _wait_for_body(url, "RULE-B", headers=host, verify=verify)
    statuses.append(status_after_c)
    assert body_after_c.strip() == "RULE-B", (
        f"after deleting the priority-1 rule the load balancer served "
        f"{body_after_c.strip()!r}, expected RULE-B (the current priority-10 rule)"
    )

    assert statuses == [200, 200, 200, 200], (
        f"one of the four requests did not return 200: {statuses!r}"
    )

    # Rule C is gone: unreadable by ARN, absent from its listener, and not modifiable.
    c_arn = rule_c["RuleArn"]
    _expect_error(lambda: elb.describe_rules(RuleArns=[c_arn]), ("RuleNotFound",))
    listed = [r["RuleArn"] for r in elb.describe_rules(ListenerArn=la)["Rules"]]
    assert c_arn not in listed, f"deleted rule {c_arn} still listed on its listener"
    _expect_error(lambda: elb.modify_rule(RuleArn=c_arn, Actions=_fixed("RULE-C2")), ("RuleNotFound",))

    # The load balancer is deleted and gone: unreadable by ARN and name, and unusable.
    lb_arn, lb_name = lb["LoadBalancerArn"], lb["LoadBalancerName"]
    _retry_throttled(lambda: elb.delete_load_balancer(LoadBalancerArn=lb_arn))
    _poll_until(
        lambda: _lb_present(elb, lb_arn),
        lambda present: present is False,
        interval_s=3.0,
        description=f"load balancer {lb_name} reading not-found after DeleteLoadBalancer",
    )
    _expect_error(lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn]), ("LoadBalancerNotFound",))
    _expect_error(lambda: elb.describe_load_balancers(Names=[lb_name]), ("LoadBalancerNotFound",))
    _expect_error(lambda: elb.create_listener(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=8080,
                                              DefaultActions=_fixed("DEAD")),
                  ("LoadBalancerNotFound",))


# ===== helpers =====
def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, a non-empty message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected a non-empty message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _lb_present(elb, arn):
    try:
        elb.describe_load_balancers(LoadBalancerArns=[arn])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
            return False
        raise
    return True


# A load balancer or instance in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation.
# Teardown waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the
# check's network deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
