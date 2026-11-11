"""e2e-http-to-https-redirect-traffic-flow."""
from __future__ import annotations

import http.client
import urllib.parse
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-http-to-https-redirect-traffic-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP listener rule redirecting to HTTPS 443 with HTTP_301 answers a real request with 301 and an https
    Location; once deleted, the listener fails with ListenerNotFound and the exact message and the load
    balancer is gone."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _provision_network(ctx)
    sg_id = _create_open_security_group(ctx, vpc_id, [80])

    lb_name = _short_name("sim2real-redir")
    lb = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids[:2],
        SecurityGroups=[sg_id],
        Scheme="internet-facing",
        Type="application",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))

    dns_name = _wait_for_lb_active(ctx, lb_arn)

    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": "404",
                    "ContentType": "text/plain",
                    "MessageBody": "no rule matched",
                },
            }
        ],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=1,
        Conditions=[{"Field": "path-pattern", "Values": ["/*"]}],
        Actions=[
            {
                "Type": "redirect",
                "RedirectConfig": {
                    "Protocol": "HTTPS",
                    "Port": "443",
                    "Host": "#{host}",
                    "Path": "/#{path}",
                    "Query": "#{query}",
                    "StatusCode": "HTTP_301",
                },
            }
        ],
    )

    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default = [r for r in rules if not r["IsDefault"]]
    assert len(non_default) == 1, f"expected exactly one non-default rule, got {non_default}"
    redirect_action = non_default[0]["Actions"][0]
    assert redirect_action["Type"] == "redirect", f"expected a redirect action, got {redirect_action['Type']!r}"
    assert redirect_action["RedirectConfig"]["Protocol"] == "HTTPS", (
        f"expected redirect protocol HTTPS, got {redirect_action['RedirectConfig']['Protocol']!r}"
    )
    assert redirect_action["RedirectConfig"]["Port"] == "443", (
        f"expected redirect port 443, got {redirect_action['RedirectConfig']['Port']!r}"
    )
    assert redirect_action["RedirectConfig"]["StatusCode"] == "HTTP_301", (
        f"expected redirect status HTTP_301, got {redirect_action['RedirectConfig']['StatusCode']!r}"
    )

    # The real traffic-path consequence: a plain HTTP GET against the live ALB is redirected.
    status, headers = _poll_http_get(ctx, dns_name, 80, "/")
    assert status == 301, f"expected 301 redirect, got {status}"
    location = headers.get("location")
    assert location is not None and location.startswith("https://"), f"unexpected Location: {location}"

    # Tear down: listener (cascades its rule) then the load balancer; both become NotFound.
    elbv2.delete_listener(ListenerArn=listener_arn)
    code, message = _error(lambda: elbv2.describe_listeners(ListenerArns=[listener_arn]))
    assert code == "ListenerNotFound", f"expected ListenerNotFound after delete, got {code!r}"
    expected_message = "One or more listeners not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    deadline = time.monotonic() + 180.0
    gone = False
    while time.monotonic() < deadline:
        try:
            code, _message = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn]))
        except AssertionError:
            code = None
        if code == "LoadBalancerNotFound":
            gone = True
            break
        time.sleep(5.0)
    assert gone, "load balancer was still describable long after DeleteLoadBalancer"


def _short_name(prefix: str, max_len: int = 32) -> str:
    suffix = uuid.uuid4().hex[:10]
    name = f"{prefix}-{suffix}"
    return name[:max_len].rstrip("-")


def _error(fn) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


def _safe_call(fn) -> None:
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s, anything else raises."""
    deadline = time.monotonic() + 180.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _provision_network(ctx, min_azs: int = 2) -> tuple[str, list[str]]:
    """A dedicated VPC with public, internet-routed subnets — never the ambient default VPC,
    which a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    cidr = "10.93.0.0/16"

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-redir-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:min_azs]
    ]
    if len(azs) < min_azs:
        raise AssertionError(f"region exposes only {len(azs)} available AZ(s); need at least {min_azs} for an ALB")

    subnet_ids: list[str] = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-redir-subnet-{i}-")}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _safe_call(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-redir-igw-")}]}]
    )["InternetGateway"]["InternetGatewayId"]

    def _teardown_igw() -> None:
        _safe_call(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
        _safe_call(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-redir-rtb-")}]}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for subnet_id in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _safe_call(lambda: ec2.disassociate_route_table(AssociationId=aid)))

    return vpc_id, subnet_ids


def _create_open_security_group(ctx, vpc_id: str, ports: list[int]) -> str:
    ec2 = ctx.client("ec2")
    sg_name = _short_name("sim2real-sg", max_len=64)
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real elbv2 behavioral test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]

    def _cleanup_sg() -> None:
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            try:
                _delete_net(ec2, "delete_security_group", GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code == "DependencyViolation":
                    time.sleep(5.0)
                    continue
                raise

    ctx.on_cleanup(_cleanup_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for p in ports
        ],
    )
    return sg_id


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        last_state = lb["State"]["Code"]
        if last_state == "active":
            return lb["DNSName"]
        if last_state == "failed":
            raise AssertionError(f"load balancer {lb_arn} entered failed state")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never became active (last state={last_state})")


def _poll_http_get(
    ctx, host: str, port: int, path: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> tuple[int, dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        conn = None
        try:
            _url, _route = ctx.endpoint_route(f"http://{host}:{port}")
            _t = urllib.parse.urlsplit(_url)
            conn = http.client.HTTPConnection(_t.hostname, _t.port or 80, timeout=10)
            conn.request("GET", path, headers=_route)
            resp = conn.getresponse()
            status = resp.status
            headers = {k.lower(): v for k, v in resp.getheaders()}
            resp.read()
            return status, headers
        except (OSError, http.client.HTTPException) as exc:  # DNS and ENIs settle after the listener is created
            last_exc = exc
            time.sleep(interval_s)
        finally:
            if conn is not None:
                conn.close()
    raise AssertionError(f"never got an HTTP response from {host}:{port}{path}: {last_exc}")


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
