"""vpc-origin-internal-alb-serves-marker-at-the-edge."""
from __future__ import annotations

import ipaddress
import socket
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-origin-internal-alb-serves-marker-at-the-edge"
GROUP = "data-plane"
SERVICES = ["cloudfront", "ec2", "elbv2"]

#: CloudFront's control plane is global and signed in us-east-1; the VPC and ALB live in ctx.region.
CLOUDFRONT_REGION = "us-east-1"

#: A VPC origin's CloudFront-side deploy and the distribution's own deploy each can take minutes.
_VPC_ORIGIN_DEPLOY_BUDGET_S = 1200.0
_DISTRIBUTION_DEPLOY_BUDGET_S = 1200.0
_EDGE_BUDGET_S = 300.0
_ALB_ACTIVE_BUDGET_S = 600.0
_ENI_CLEAR_BUDGET_S = 900.0
_NETWORK_DELETE_BUDGET_S = 900.0

#: The origin header CloudFront adds and the ALB's listener rule requires; anything without it gets
#: the listener's fixed 403.
SECRET_HEADER = "X-Origin-Secret"
DENIED_BODY = "sim2real-request-without-origin-secret-denied"


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    """Bounded retry that RAISES on timeout, never returning a stale last value as success."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _retry_dependency_violation(fn, *not_found_codes, deadline, interval_s=5.0):
    """Call ``fn()``; swallow the resource's own not-found codes, retry DependencyViolation."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in not_found_codes:
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _delete_network(ec2, net, *, budget_s=_NETWORK_DELETE_BUDGET_S):
    """Delete the SG, subnets, the IGW and the VPC this check created, in that dependency order;
    ``net`` is filled in as each is created, so a setup that fails part-way is still torn down.

    CloudFront's own service-managed ENI and security group for the VPC origin are never touched
    here; they are not ours to delete, and waiting for their ENIs lets the subnet deletes proceed.
    """
    vpc_id = net["vpc"]
    deadline = time.monotonic() + budget_s
    _poll_until(
        lambda: len(ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]),
        lambda n: n == 0,
        timeout_s=max(1.0, deadline - time.monotonic()),
        interval_s=15.0,
        description=f"every ENI in {vpc_id} to go",
    )
    if net["sg"]:
        _retry_dependency_violation(
            lambda: ec2.delete_security_group(GroupId=net["sg"]),
            "InvalidGroup.NotFound", deadline=deadline,
        )
    for subnet_id in net["subnets"]:
        _retry_dependency_violation(
            lambda s=subnet_id: ec2.delete_subnet(SubnetId=s),
            "InvalidSubnetID.NotFound", deadline=deadline,
        )
    if net["igw"]:
        _retry_dependency_violation(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=vpc_id),
            "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound", deadline=deadline,
        )
        _retry_dependency_violation(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]),
            "InvalidInternetGatewayID.NotFound", deadline=deadline,
        )
    _retry_dependency_violation(
        lambda: ec2.delete_vpc(VpcId=vpc_id),
        "InvalidVpcID.NotFound", deadline=deadline,
    )


def _delete_load_balancer(elb, lb_arn) -> None:
    """Delete the ALB and wait until it is gone, so its ENIs clear before the network teardown."""
    try:
        elb.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return
        raise
    elb.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 450})


def _delete_vpc_origin(cf, vo_id, *, timeout_s=_VPC_ORIGIN_DEPLOY_BUDGET_S) -> None:
    """Wait for the VPC origin to reach Deployed (delete is illegal before that), then delete it.

    Tolerates a concurrent not-found at every step.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            origin = cf.get_vpc_origin(Id=vo_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityNotFound":
                return
            raise
        if origin["VpcOrigin"]["Status"] == "Deployed":
            etag = origin["ETag"]
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"VPC origin {vo_id} still {origin['VpcOrigin']['Status']!r} after {timeout_s}s"
            )
        time.sleep(15)
    try:
        cf.delete_vpc_origin(Id=vo_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            cf.get_vpc_origin(Id=vo_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityNotFound":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"VPC origin {vo_id} still present {timeout_s}s after delete")


def _delete_distribution(cf, dist_id, *, timeout_s=_DISTRIBUTION_DEPLOY_BUDGET_S) -> None:
    """Disable the distribution, wait until the change reaches Deployed, then delete it."""
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda st: st == "Deployed",
        timeout_s=timeout_s, interval_s=20.0,
        description=f"disabled distribution {dist_id} to reach Deployed",
    )
    cf.delete_distribution(Id=dist_id, IfMatch=cf.get_distribution(Id=dist_id)["ETag"])


def _edge_get(session, url, headers, verify):
    """One GET through the edge; a transport error while the edge propagates is returned."""
    try:
        return session.get(url, headers=headers, timeout=20, verify=verify)
    except requests.RequestException as exc:
        return exc


def _caching_disabled_policy_id(cf) -> str:
    """The Id of the AWS-managed cache policy named Managed-CachingDisabled."""
    for item in cf.list_cache_policies(Type="managed")["CachePolicyList"]["Items"]:
        if item["CachePolicy"]["CachePolicyConfig"]["Name"] == "Managed-CachingDisabled":
            return item["CachePolicy"]["Id"]
    raise AssertionError("no managed cache policy named Managed-CachingDisabled")


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFront VPC origin backed by an internal ALB serves, at the edge, the body of the
    listener rule matching the origin custom header CloudFront adds; the ALB's Scheme is internal
    and its DNS name resolves only to private addresses.
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)

    name = ctx.unique_name("sim2real-vo-")
    marker = ctx.unique_name("sim2real-via-edge-")
    secret = ctx.unique_name("sim2real-secret-")

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"need 2 available AZs in {ctx.region}, found {zones!r}"

    vpc_id = ec2.create_vpc(
        CidrBlock="10.61.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    net = {"vpc": vpc_id, "igw": None, "subnets": [], "sg": None}
    ctx.on_cleanup(lambda: _delete_network(ec2, net))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway",
                            "Tags": [{"Key": "Name", "Value": name}]}],
    )["InternetGateway"]["InternetGatewayId"]
    net["igw"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    for i, az in enumerate(zones[:2]):
        net["subnets"].append(ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.61.{i + 1}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet",
                                "Tags": [{"Key": "Name", "Value": name}]}],
        )["Subnet"]["SubnetId"])
    subnet_ids = net["subnets"]

    origin_facing = ec2.describe_managed_prefix_lists(Filters=[{
        "Name": "prefix-list-name", "Values": ["com.amazonaws.global.cloudfront.origin-facing"],
    }])["PrefixLists"][0]["PrefixListId"]
    sg_id = ec2.create_security_group(
        GroupName=name, Description=CHECK, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    net["sg"] = sg_id
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "PrefixListIds": [{"PrefixListId": origin_facing}],
    }])

    lb_arn = elb.create_load_balancer(
        Name=name[:32].rstrip("-"), Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internal",
        Type="application", IpAddressType="ipv4", Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elb, lb_arn))

    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "403", "ContentType": "text/plain", "MessageBody": DENIED_BODY}}],
    )["Listeners"][0]["ListenerArn"]
    elb.create_rule(
        ListenerArn=listener_arn, Priority=1,
        Conditions=[{"Field": "http-header", "HttpHeaderConfig": {
            "HttpHeaderName": SECRET_HEADER, "Values": [secret]}}],
        Actions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": marker}}],
    )

    alb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda a: a["State"]["Code"] == "active",
        timeout_s=_ALB_ACTIVE_BUDGET_S, interval_s=10.0, description=f"ALB {name} to become active",
    )
    alb_dns = alb["DNSName"]

    create_resp = cf.create_vpc_origin(VpcOriginEndpointConfig={
        "Name": name, "Arn": lb_arn, "HTTPPort": 80, "HTTPSPort": 443,
        "OriginProtocolPolicy": "http-only",
    })
    vo_id = create_resp["VpcOrigin"]["Id"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(cf, vo_id))
    _poll_until(
        lambda: cf.get_vpc_origin(Id=vo_id)["VpcOrigin"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=_VPC_ORIGIN_DEPLOY_BUDGET_S, interval_s=20.0,
        description=f"VPC origin {vo_id} to reach Deployed",
    )

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-vo-cr-"),
        "Comment": name,
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "vpc-origin",
            "DomainName": alb_dns,
            "CustomHeaders": {"Quantity": 1, "Items": [
                {"HeaderName": SECRET_HEADER, "HeaderValue": secret}]},
            "VpcOriginConfig": {"VpcOriginId": vo_id},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "vpc-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _caching_disabled_policy_id(cf),
        },
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))

    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda st: st == "Deployed",
        timeout_s=_DISTRIBUTION_DEPLOY_BUDGET_S, interval_s=20.0,
        description=f"distribution {dist_id} to reach Deployed",
    )

    session = requests.Session()
    session.trust_env = False
    edge, route = ctx.endpoint_route(dist["DomainName"])
    url = f"{edge}/sim2real/resource"
    via_edge = _poll_until(
        lambda: _edge_get(session, url, route, ctx.http_verify),
        lambda r: isinstance(r, requests.Response) and r.status_code == 200,
        timeout_s=_EDGE_BUDGET_S, interval_s=10.0, description="200 through the distribution",
    )
    assert via_edge.text == marker, (
        f"expected the ALB's fixed-response body {marker!r} at the edge, got "
        f"{via_edge.text[:200]!r}"
    )

    scheme = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["Scheme"]
    assert scheme == "internal", f"expected ALB Scheme 'internal', got {scheme!r}"

    _, _, addrs = _poll_until(
        lambda: _resolve(alb_dns),
        lambda r: r is not None,
        timeout_s=120.0, interval_s=10.0, description=f"DNS resolution of {alb_dns}",
    )
    not_private = [a for a in addrs if not ipaddress.ip_address(a).is_private]
    assert not_private == [], (
        f"the internal ALB's DNS name {alb_dns} resolved to a non-private address: {not_private!r}"
    )


def _resolve(host):
    try:
        return socket.gethostbyname_ex(host)
    except socket.gaierror:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
