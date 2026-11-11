"""xsvc-cloudfront-2-alb-origin-protocol-policy-mismatch-rejected."""
from __future__ import annotations

import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-2-alb-origin-protocol-policy-mismatch-rejected"
GROUP = "origin-enforcement"
SERVICES = ["cloudfront", "elbv2"]

#: CloudFront's control plane is global and signed in us-east-1; the VPC and ALB live in ctx.region.
CLOUDFRONT_REGION = "us-east-1"

#: Marker a FAIL detail carries when the target's endpoint data plane is unimplemented.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: every edge request reaches the ALB.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: What CloudFront answers when it cannot open the origin connection its policy demands (for an ALB
#: whose security group admits tcp/80 only).
ORIGIN_UNREACHABLE_STATUS = 504

_TAG = {"Key": "sim2real", "Value": "xsvc-cloudfront-2"}


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _tagspec(kind, name):
    return [{"ResourceType": kind, "Tags": [_TAG, {"Key": "Name", "Value": name}]}]


def _teardown_vpc(ec2, vpc_id, *, budget_s=300.0) -> None:
    """Delete everything this check put in its own VPC, then the VPC; registered first, runs LAST.

    Lingering ALB ENIs can hold the SG and subnets (DependencyViolation), so each delete retries
    only that code inside a shared budget; a VPC that does not converge raises with its id.
    """
    deadline = time.monotonic() + budget_s

    def retry(fn):
        while True:
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code.endswith("NotFound"):
                    return None
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
                time.sleep(3)

    filt = [{"Name": "vpc-id", "Values": [vpc_id]}]
    try:
        for sg in ec2.describe_security_groups(Filters=filt)["SecurityGroups"]:
            if sg["GroupName"] != "default":
                retry(lambda g=sg["GroupId"]: ec2.delete_security_group(GroupId=g))
        for sn in ec2.describe_subnets(Filters=filt)["Subnets"]:
            retry(lambda s=sn["SubnetId"]: ec2.delete_subnet(SubnetId=s))
        for rt in ec2.describe_route_tables(Filters=filt)["RouteTables"]:
            if not any(a.get("Main") for a in rt.get("Associations", [])):
                retry(lambda r=rt["RouteTableId"]: ec2.delete_route_table(RouteTableId=r))
        for igw in ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]:
            retry(lambda i=igw["InternetGatewayId"]: ec2.detach_internet_gateway(
                InternetGatewayId=i, VpcId=vpc_id))
            retry(lambda i=igw["InternetGatewayId"]: ec2.delete_internet_gateway(
                InternetGatewayId=i))
        retry(lambda: ec2.delete_vpc(VpcId=vpc_id))
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            teardown_code not in ("Gateway.NotAttached", "InvalidGroup.NotFound", "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound")
            and not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f"vpc {vpc_id} (and what remains in it): {exc!r}") from exc


def _delete_distribution(cf, dist_id, *, timeout_s=900.0) -> None:
    """Disable the distribution, wait until the change is Deployed, then delete it.

    The wait is bounded at 900 s so the ALB delete (300 s) and VPC teardown (300 s) still fit.
    """
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
        timeout_s=timeout_s,
        interval_s=20.0,
        description=f"disabled distribution {dist_id} to reach Deployed",
    )
    cf.delete_distribution(Id=dist_id, IfMatch=cf.get_distribution(Id=dist_id)["ETag"])


def _delete_load_balancer(elb, lb_arn) -> None:
    """Delete the ALB and wait until it is gone, so its ENIs leave the VPC before its teardown."""
    try:
        elb.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return
        raise
    elb.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _public_alb(ctx, ec2, elb, name):
    """A self-owned VPC with two public subnets and an internet-facing ALB allowing tcp/80 only."""
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"an ALB needs two available AZs in {ctx.region}, found {zones!r}"

    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16",
                            TagSpecifications=_tagspec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown_vpc(ctx.client("ec2"), vpc_id))
    igw = ec2.create_internet_gateway(
        TagSpecifications=_tagspec("internet-gateway", name))["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    rt = ec2.create_route_table(VpcId=vpc_id,
                                TagSpecifications=_tagspec("route-table", name))["RouteTable"]
    ec2.create_route(RouteTableId=rt["RouteTableId"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw)
    subnets = []
    for i, az in enumerate(zones[:2]):
        sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i + 1}.0/24", AvailabilityZone=az,
                               TagSpecifications=_tagspec("subnet", name))["Subnet"]["SubnetId"]
        ec2.associate_route_table(RouteTableId=rt["RouteTableId"], SubnetId=sn)
        subnets.append(sn)
    sg = ec2.create_security_group(GroupName=name, Description="sim2real alb http only",
                                   VpcId=vpc_id,
                                   TagSpecifications=_tagspec("security-group", name))["GroupId"]
    # Only CloudFront connects to the ALB, from its origin-facing ranges (the AWS-managed prefix list).
    origin_facing = ec2.describe_managed_prefix_lists(Filters=[{
        "Name": "prefix-list-name", "Values": ["com.amazonaws.global.cloudfront.origin-facing"],
    }])["PrefixLists"][0]["PrefixListId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "PrefixListIds": [{"PrefixListId": origin_facing}],
    }])

    lb = elb.create_load_balancer(Name=name, Subnets=subnets, SecurityGroups=[sg],
                                  Scheme="internet-facing", Type="application",
                                  IpAddressType="ipv4", Tags=[_TAG])["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(ctx.client("elbv2"), lb_arn))
    return lb_arn, lb["DNSName"]


def _get(ctx, session, url, **kw):
    try:
        _url, _route = ctx.endpoint_route(url)
        return session.get(_url, timeout=20, **{**kw, "headers": {**kw.get("headers", {}), **_route}})
    except requests.RequestException as exc:  # transport only (DNS / provisioning)
        return exc


def _origin(origin_id, dns, policy):
    return {
        "Id": origin_id,
        "DomainName": dns,
        "CustomOriginConfig": {
            "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": policy,
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
        },
        # One 2 s attempt: the mismatch must fail fast and deterministically, not after
        # CloudFront's default three 10 s attempts.
        "ConnectionAttempts": 1,
        "ConnectionTimeout": 2,
    }


def _behavior(pattern, origin_id):
    return {
        "PathPattern": pattern,
        "TargetOriginId": origin_id,
        "ViewerProtocolPolicy": "allow-all",
        "CachePolicyId": MANAGED_CACHING_DISABLED,
    }


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """OriginProtocolPolicy decides which port CloudFront dials; a policy the ALB cannot serve fails.
    Against one HTTP-only ALB, http-only and match-viewer over HTTP return 200 with the marker,
    while https-only and match-viewer over HTTPS return 504 from the edge without it.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")

    name = ctx.unique_name("sim2real-xsvc-alb-")
    marker = ctx.unique_name("sim2real-alb-http-")

    lb_arn, alb_dns = _public_alb(ctx, ec2, elb, name)
    elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": marker}}],
    )

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-xsvc-alb-cr-"),
        "Comment": "sim2real xsvc-cloudfront-2 alb origin protocol policy",
        "Enabled": True,
        "Origins": {"Quantity": 3, "Items": [
            _origin("alb-http-only", alb_dns, "http-only"),
            _origin("alb-https-only", alb_dns, "https-only"),
            _origin("alb-match-viewer", alb_dns, "match-viewer"),
        ]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "alb-http-only",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
        },
        "CacheBehaviors": {"Quantity": 2, "Items": [
            _behavior("/tls/*", "alb-https-only"),
            _behavior("/mv/*", "alb-match-viewer"),
        ]},
        "CustomErrorResponses": {"Quantity": 1, "Items": [
            {"ErrorCode": ORIGIN_UNREACHABLE_STATUS, "ErrorCachingMinTTL": 0}]},
    })["Distribution"]
    dist_id, domain = dist["Id"], dist["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))

    _poll_until(lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
                ["LoadBalancers"][0]["State"]["Code"],
                lambda s: s == "active", timeout_s=600.0, interval_s=10.0,
                description=f"ALB {name} to become active")
    _poll_until(lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
                lambda s: s == "Deployed", timeout_s=900.0, interval_s=10.0,
                description=f"distribution {dist_id} to reach Deployed")

    session = requests.Session()
    session.trust_env = False

    # BEAT 1 — positive control: the protocol the ALB speaks.
    try:
        # tls: the origin protocol follows the viewer scheme named here, which is the subject
        ok = _poll_until(lambda: _get(ctx, session, f"https://{domain}/plain/a"),
                         lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                         timeout_s=300.0, interval_s=10.0,
                         description="200 through the http-only origin")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    assert ok.text == marker, f"the http-only origin must serve the ALB's body, got {ok.text[:200]!r}"

    # BEAT 2 — mismatch: https-only against an ALB with no reachable 443.
    # tls: the origin protocol follows the viewer scheme named here, which is the subject
    _url, _route = ctx.endpoint_route(f"https://{domain}/tls/a")
    tls = session.get(_url, timeout=30, headers=_route)
    assert tls.status_code == ORIGIN_UNREACHABLE_STATUS, (
        f"an https-only origin on an HTTP-only ALB must fail at the edge with "
        f"{ORIGIN_UNREACHABLE_STATUS}, got {tls.status_code!r} / {tls.text[:200]!r}"
    )
    assert marker not in tls.text, f"the mismatch leaked the ALB's body: {tls.text[:200]!r}"

    # BEAT 3 — match-viewer with an HTTP viewer dials 80.
    _url, _route = ctx.endpoint_route(f"http://{domain}/mv/a")
    mv_http = session.get(_url, timeout=30, headers=_route)
    assert (mv_http.status_code, mv_http.text) == (200, marker), (
        f"match-viewer with an HTTP viewer must reach the ALB on 80, got "
        f"{(mv_http.status_code, mv_http.text[:200])!r}"
    )

    # BEAT 4 — the SAME origin with an HTTPS viewer dials 443 and fails.
    # tls: the origin protocol follows the viewer scheme named here, which is the subject
    _url, _route = ctx.endpoint_route(f"https://{domain}/mv/a")
    mv_https = session.get(_url, timeout=30, headers=_route)
    assert mv_https.status_code == ORIGIN_UNREACHABLE_STATUS, (
        f"match-viewer with an HTTPS viewer must dial 443 and fail with "
        f"{ORIGIN_UNREACHABLE_STATUS}, got {mv_https.status_code!r} / {mv_https.text[:200]!r}"
    )
    assert marker not in mv_https.text, (
        f"the HTTPS match-viewer leg leaked the ALB's body: {mv_https.text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
