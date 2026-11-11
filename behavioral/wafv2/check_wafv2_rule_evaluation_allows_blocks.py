"""wafv2-rule-evaluation-allows-blocks."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "wafv2-rule-evaluation-allows-blocks"
GROUP = 'rule-evaluation'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient errors (throttling, entity not yet resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    try:
        lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
        deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except Exception as exc:  # noqa: BLE001 - already-gone is fine, anything else is a leak
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code != "WAFNonexistentItemException":
            raise

def _create_public_network(ctx, ec2, tags):
    """Create a VPC with 2 subnets in distinct AZs routed to an Internet Gateway, for an ALB.

    Registered for teardown first, so LIFO cleanup deletes it after the ALB and security group.
    """
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    try:
        ec2.create_tags(Resources=[vpc_id], Tags=tags)
    except Exception:
        pass

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    try:
        ec2.create_tags(Resources=[igw_id], Tags=tags)
    except Exception:
        pass

    rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError("region lacks >= 2 available AZs for an ALB")
    subnet_ids = []
    for i in range(2):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.99.{i}.0/24", AvailabilityZone=azs[i]["ZoneName"],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        try:
            ec2.create_tags(Resources=[subnet_id], Tags=tags)
        except Exception:
            pass
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: ec2.disassociate_route_table(AssociationId=aid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _create_webacl(ctx, w, name=None, rules=None, scope=SCOPE, default_allow=True, tags=None):
    """Create a WebACL registered for teardown and return its Summary."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    summary = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction={"Allow": {}} if default_allow else {"Block": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")[:128]),
            Tags=tags or [],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, summary["Id"]))
    return summary


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A WebACL associated with a live internet-facing ALB blocks requests carrying x-waf-block: 1
    with 403 and lets requests without the header through to the 200 fixed-response listener.
    """

    import requests

    w = ctx.client("wafv2")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    _tags = [{"Key": "sim2real:managed", "Value": "true"},
             {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    rules = [
        {
            "Name": "block-header",
            "Priority": 0,
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": b"1",
                    "FieldToMatch": {"SingleHeader": {"Name": "x-waf-block"}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "EXACTLY",
                }
            },
            "Action": {"Block": {}},
            "VisibilityConfig": _visibility_config("blockheader"),
        }
    ]
    acl = _create_webacl(ctx, w, rules=rules, default_allow=True, tags=_tags)
    acl_arn = acl["ARN"]

    vpc_id, subnet_ids = _create_public_network(ctx, ec2, _tags)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-waf-sg-"),
        Description="sim2real wafv2 live ALB",
        VpcId=vpc_id,
    )["GroupId"]
    # Runs after the load balancer teardown below (LIFO), once its ENIs have left the group.
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    try:
        ec2.create_tags(Resources=[sg_id], Tags=_tags)
    except Exception:
        pass
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()],
            }
        ],
    )

    lb_name = "sim2real-wafalb-" + ctx.unique_name("")[-8:]
    lb = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internet-facing",
        Type="application",
        Tags=_tags,
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    dns = lb["DNSName"]

    # ELB teardown BEFORE the WebACL delete (registered by _create_webacl): a WebACL cannot be
    # deleted while associated with a load balancer. Registered right after the create, so a
    # failure anywhere below still removes the load balancer and its listener.
    def _teardown_elb():
        try:
            w.disassociate_web_acl(ResourceArn=lb_arn)
        except w.exceptions.WAFNonexistentItemException:
            pass  # already disassociated
        finally:
            # Runs even when the disassociate raised, so the load balancer never leaks.
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        # The security group delete needs the ALB gone; 180 s here plus its 630 s ENI wait fit
        # within a 900 s cleanup budget.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
            except elbv2.exceptions.LoadBalancerNotFoundException:
                return
            time.sleep(2)
        raise RuntimeError(f"wafv2 ALB teardown failed: load balancer {lb_arn} still present 180s after delete")

    ctx.on_cleanup(_teardown_elb)

    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": "200",
                    "ContentType": "text/plain",
                    "MessageBody": "ok",
                },
            }
        ],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_listener(elbv2, listener_arn))

    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        code = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]
        if code == "active":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"ALB {lb_arn} not active within 300s (last state {code!r})")

    _retry_transient(
        lambda: w.associate_web_acl(WebACLArn=acl_arn, ResourceArn=lb_arn),
        attempts=6,
        delay=12.0,
        codes=_TRANSIENT_CODES,
    )

    url = f"http://{dns}/"
    saw_response = {"any": False}

    def allowed_status():
        try:
            target_url, route_headers = ctx.endpoint_route(url)
            r = requests.get(target_url, timeout=10, headers=route_headers)
            saw_response["any"] = True
            return r.status_code
        except (requests.ConnectionError, requests.Timeout):  # LB warmup / reachability
            return None

    deadline = time.monotonic() + 300
    ok = False
    while time.monotonic() < deadline:
        if allowed_status() == 200:
            ok = True
            break
        time.sleep(2)
    if not ok:
        if not saw_response["any"]:
            raise AssertionError("internet-facing ALB not reachable from this runner")
        raise AssertionError("allowed request never reached the ALB (200)")

    def blocked_status():
        try:
            target_url, route_headers = ctx.endpoint_route(url)
            return requests.get(target_url, headers={"x-waf-block": "1", **route_headers}, timeout=10).status_code
        except (requests.ConnectionError, requests.Timeout):
            return None

    deadline = time.monotonic() + 180
    blocked_ok = False
    while time.monotonic() < deadline:
        if blocked_status() == 403:
            blocked_ok = True
            break
        time.sleep(2)
    assert blocked_ok, "blocked request never rejected by WAF (403)"

    assert allowed_status() == 200, "allowed request should still return 200 under WAF"


def _delete_listener(elbv2, listener_arn):
    """Delete a listener; one already removed with its load balancer is fine."""
    try:
        elbv2.delete_listener(ListenerArn=listener_arn)
    except elbv2.exceptions.ListenerNotFoundException:
        pass


# A load balancer in the VPC deletes asynchronously and its ENIs linger, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Network deletes
# wait (bounded, one shared window) for ENIs to go, retry DependencyViolation, then raise naming
# the ENIs still attached.
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
