"""deep-apigateway-3-apigw-private-vpclink-positive."""
from __future__ import annotations

import random
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigateway-3-apigw-private-vpclink-positive"
GROUP = "vpc-link"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A REST VPC_LINK integration serves a private ALB's own bytes and status on a public stage.

    The VpcLink must be observed PENDING then AVAILABLE; matched and unmatched paths return
    distinct per-run backend bodies, so the path is forwarded and the backend status passes through.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-private-integration.html
    """
    # Teardown (VPC link, two load balancers' ENIs, the VPC) takes minutes, longer than the 60s
    # cleanup bound after run(), so the check drains its own cleanups.
    try:
        _body(ctx)
    finally:
        ctx.run_cleanups()


def _body(ctx) -> None:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    apigw = ctx.client("apigateway")
    hit_body = f"sim2real-hit-{ctx.unique_name('')}"
    miss_body = f"sim2real-miss-{ctx.unique_name('')}"

    # ---- decidable preconditions first: two available, non-opt-in AZs ----
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus") == "opt-in-not-required"
    )
    assert len(zones) >= 2, f"an ALB needs two AZs; region {ctx.region!r} offered {zones!r}"

    # ---- network: an isolated VPC with no internet gateway ----
    octet = random.randint(16, 250)
    cidr = f"10.{octet}.0.0/16"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags(ctx, "vpc")}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(
        lambda: _ignore(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"), vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_ids = []
    for i, az in enumerate(zones[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.{octet}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(ctx, f"subnet{i}")}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_when_drained(
            ec2, "subnet-id", sid,
            lambda: _ignore(lambda: ec2.delete_subnet(SubnetId=sid), "InvalidSubnetID.NotFound")))
        subnet_ids.append(sid)
    ec2.get_waiter("subnet_available").wait(SubnetIds=subnet_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-albsg-"), Description="sim2real vpclink alb",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags(ctx, "albsg")}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_drained(
        ec2, "group-id", sg_id,
        lambda: _ignore(lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound")))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                        "IpRanges": [{"CidrIp": cidr}]}],
    )

    # ---- backend: an internal ALB whose fixed responses ARE the backend content ----
    alb = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"), Subnets=subnet_ids, SecurityGroups=[sg_id],
        Scheme="internal", Type="application", Tags=_tags(ctx, "alb"),
    )["LoadBalancers"][0]
    alb_arn = alb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb(elbv2, alb_arn))

    nlb = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-nlb-"), Subnets=subnet_ids,
        Scheme="internal", Type="network", Tags=_tags(ctx, "nlb"),
    )["LoadBalancers"][0]
    nlb_arn, nlb_dns = nlb["LoadBalancerArn"], nlb["DNSName"]
    ctx.on_cleanup(lambda: _delete_lb(elbv2, nlb_arn))

    _poll(ctx, lambda: _lb_state(elbv2, alb_arn), lambda code: code == "active",
          timeout_s=_budget_s(ctx, 900), interval_s=2, what="load balancer active")
    alb_listener = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "404", "ContentType": "text/plain", "MessageBody": miss_body}}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: elbv2.delete_listener(ListenerArn=alb_listener),
                                   "ListenerNotFound"))
    elbv2.create_rule(
        ListenerArn=alb_listener, Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/hello"]}}],
        Actions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": hit_body}}],
    )

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"), TargetType="alb", Protocol="TCP", Port=80,
        VpcId=vpc_id, HealthCheckProtocol="HTTP", HealthCheckPath="/hello",
        Tags=_tags(ctx, "tg"),
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn),
                                   "TargetGroupNotFound"))
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": alb_arn, "Port": 80}])

    _poll(ctx, lambda: _lb_state(elbv2, nlb_arn), lambda code: code == "active",
          timeout_s=_budget_s(ctx, 900), interval_s=2, what="load balancer active")
    nlb_listener = elbv2.create_listener(
        LoadBalancerArn=nlb_arn, Protocol="TCP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: elbv2.delete_listener(ListenerArn=nlb_listener),
                                   "ListenerNotFound"))
    _poll(
        ctx, lambda: [t["TargetHealth"]["State"] for t in
                 elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]],
        lambda states: states == ["healthy"],
        timeout_s=_budget_s(ctx, 600), interval_s=2, what="NLB target (the ALB) healthy",
    )

    # ---- the VpcLink state machine: PENDING must be observed before AVAILABLE ----
    link = apigw.create_vpc_link(
        name=ctx.unique_name("sim2real-vpclink-"), targetArns=[nlb_arn],
        description="sim2real vpclink positive", tags={"sim2real": CHECK},
    )
    link_id = link["id"]
    ctx.on_cleanup(lambda: _delete_vpc_link(apigw, link_id))
    observed = [link["status"]]
    deadline = time.monotonic() + _budget_s(ctx, 1200)
    while True:
        status = apigw.get_vpc_link(vpcLinkId=link_id)["status"]
        if status != observed[-1]:
            observed.append(status)
        if status in ("AVAILABLE", "FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(1)
    assert observed[0] == "PENDING", (
        f"CreateVpcLink returned status {observed[0]!r}; a link to a fresh NLB must start PENDING"
    )
    if observed[-1] not in ("AVAILABLE", "FAILED") and _budget_spent(ctx):
        raise TimeoutError(f"VpcLink {link_id} reaching AVAILABLE: the run budget ended first; not graded")
    assert observed[-1] == "AVAILABLE", (
        f"VpcLink never reached AVAILABLE; observed transitions {observed!r}"
    )
    assert observed == ["PENDING", "AVAILABLE"], (
        f"VpcLink status sequence {observed!r}, expected exactly PENDING then AVAILABLE"
    )

    # ---- a REGIONAL REST API proxying {proxy+} through the link ----
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-vpclink-api-"),
        endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore(lambda: apigw.delete_rest_api(restApiId=api_id),
                                   "NotFoundException"))
    root_id = next(i["id"] for i in apigw.get_resources(restApiId=api_id)["items"]
                   if i["path"] == "/")
    proxy_id = apigw.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="{proxy+}")["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=proxy_id, httpMethod="ANY", authorizationType="NONE",
        requestParameters={"method.request.path.proxy": True},
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=proxy_id, httpMethod="ANY", type="HTTP_PROXY",
        integrationHttpMethod="ANY", uri=f"http://{nlb_dns}/{{proxy}}",
        connectionType="VPC_LINK", connectionId=link_id,
        requestParameters={"integration.request.path.proxy": "method.request.path.proxy"},
    )
    integ = apigw.get_integration(restApiId=api_id, resourceId=proxy_id, httpMethod="ANY")
    assert (integ.get("connectionType"), integ.get("connectionId")) == ("VPC_LINK", link_id), (
        f"integration did not persist the VPC link: {integ.get('connectionType')!r} "
        f"{integ.get('connectionId')!r}"
    )
    apigw.create_deployment(restApiId=api_id, stageName="live")
    base = _invoke_url(ctx, api_id, "live")

    # ---- the data plane: the backend's bytes, not merely a status ----
    status, ctype, body = _poll(
        ctx, lambda: _http_get(f"{base}/hello"),
        lambda r: r[0] == 200 and r[2] == hit_body.encode(),
        timeout_s=_budget_s(ctx, 300), interval_s=2, what="matched path through the VPC link",
    )
    assert body == hit_body.encode(), f"backend body {body!r}, expected {hit_body!r}"
    assert ctype.split(";")[0].strip() == "text/plain", (
        f"backend content type did not pass through: {ctype!r}"
    )

    status, ctype, body = _poll(
        ctx, lambda: _http_get(f"{base}/elsewhere"),
        lambda r: r[0] != 500,
        timeout_s=_budget_s(ctx, 120), interval_s=2, what="unmatched path settling past a gateway 500",
    )
    assert status == 404, (
        f"unmatched path returned {status!r}; the ALB default action's 404 must pass through"
    )
    assert body == miss_body.encode(), (
        f"unmatched path body {body!r}, expected the default action's {miss_body!r} — "
        "the {proxy} path was not forwarded to the backend intact"
    )


def _lb_state(elbv2, arn):
    try:
        return elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
            return None
        raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _tags(ctx, role):
    return [{"Key": "Name", "Value": f"sim2real-{role}"}, {"Key": "sim2real", "Value": CHECK}]


def _ignore(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _poll(ctx, probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last={value!r}")
        time.sleep(interval_s)


def _http_get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def _invoke_url(ctx, rest_api_id, stage):
    return ctx.rest_api_url(rest_api_id, stage)


def _delete_vpc_link(apigw, link_id):
    """Delete, then wait until the link is gone: the NLB cannot be deleted while it is linked."""
    _ignore(lambda: apigw.delete_vpc_link(vpcLinkId=link_id), "NotFoundException")
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            apigw.get_vpc_link(vpcLinkId=link_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"VPC link {link_id} still present 900s after delete")


def _delete_lb(elbv2, arn):
    _ignore(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn), "LoadBalancerNotFound")
    elbv2.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _delete_when_drained(ec2, filter_name, value, delete):
    """Load-balancer ENIs are released asynchronously after the LB is gone, and EC2 keeps
    reporting DependencyViolation for a while after the last ENI disappears — so wait for the
    ENIs, then retry the delete (bounded) while the reference is still being revoked."""
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": filter_name, "Values": [value]}])["NetworkInterfaces"]
        if not enis:
            break
        time.sleep(2)
    _retry_dependency(delete, value)


def _retry_dependency(delete, label):
    deadline = time.monotonic() + 420
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation":
                raise RuntimeError(f"{label}: {exc}") from exc
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: still DependencyViolation after 420s") from exc
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
