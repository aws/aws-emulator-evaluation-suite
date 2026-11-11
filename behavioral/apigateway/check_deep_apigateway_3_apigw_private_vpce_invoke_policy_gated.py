"""deep-apigateway-3-apigw-private-vpce-invoke-policy-gated."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigateway-3-apigw-private-vpce-invoke-policy-gated"
GROUP = "private-endpoint"
SERVICES = ["apigateway"]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A private REST API reached through its execute-api VPC endpoint (via a VPC link and NLB)
    serves its nonce only while its aws:SourceVpce policy names that endpoint; otherwise it is 403.
    """
    # Post-check cleanup is time-bounded, and deleting a VPC link, NLB, interface endpoint and
    # their network takes minutes, so the registered cleanups are drained here.
    try:
        _body(ctx)
    finally:
        ctx.run_cleanups()


def _body(ctx) -> None:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    apigw = ctx.client("apigateway")
    nonce = f"sim2real-vpce-{ctx.unique_name('')}"
    service_name = f"com.amazonaws.{ctx.region}.execute-api"

    # Two AZs that also host the execute-api endpoint.
    svc = ec2.describe_vpc_endpoint_services(ServiceNames=[service_name])["ServiceDetails"]
    assert svc, f"{service_name!r} is not offered in {ctx.region!r}"
    offered = set(svc[0]["AvailabilityZones"])
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus") == "opt-in-not-required" and z["ZoneName"] in offered
    )
    assert len(zones) >= 2, f"need two AZs hosting {service_name}; usable were {zones!r}"

    # An isolated VPC with no internet gateway.
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
        GroupName=ctx.unique_name("sim2real-vpcesg-"), Description="sim2real execute-api vpce",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags(ctx, "vpcesg")}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_drained(
        ec2, "group-id", sg_id,
        lambda: _ignore(lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound")))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": cidr}]}],
    )

    # The execute-api interface endpoint: the only way into the private API.
    vpce_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface", VpcId=vpc_id, ServiceName=service_name,
        SubnetIds=subnet_ids, SecurityGroupIds=[sg_id], PrivateDnsEnabled=False,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _tags(ctx, "vpce")}],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpce(ec2, vpce_id))

    nlb = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-nlb-"), Subnets=subnet_ids,
        Scheme="internal", Type="network", Tags=_tags(ctx, "nlb"),
    )["LoadBalancers"][0]
    nlb_arn = nlb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb(elbv2, nlb_arn))

    vpce = _poll(
        ctx, lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0],
        lambda e: e["State"].lower() in ("available", "failed"),
        timeout_s=_budget_s(ctx, 600), interval_s=2, what="execute-api VPC endpoint available",
    )
    assert vpce["State"].lower() == "available", f"VPC endpoint ended {vpce['State']!r}"
    eni_ids = vpce["NetworkInterfaceIds"]
    assert len(eni_ids) == 2, f"expected one endpoint ENI per subnet, got {eni_ids!r}"
    vpce_ips = sorted(
        e["PrivateIpAddress"]
        for e in ec2.describe_network_interfaces(NetworkInterfaceIds=eni_ids)["NetworkInterfaces"]
    )

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"), TargetType="ip", Protocol="TCP", Port=443,
        VpcId=vpc_id, HealthCheckProtocol="TCP", Tags=_tags(ctx, "tg"),
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn),
                                   "TargetGroupNotFound"))
    elbv2.register_targets(TargetGroupArn=tg_arn,
                           Targets=[{"Id": ip, "Port": 443} for ip in vpce_ips])

    def _nlb_state():
        try:
            return elbv2.describe_load_balancers(
                LoadBalancerArns=[nlb_arn])["LoadBalancers"][0]["State"]["Code"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return None
            raise

    _poll(ctx, _nlb_state, lambda code: code == "active",
          timeout_s=_budget_s(ctx, 900), interval_s=2, what="NLB active")
    nlb_listener = elbv2.create_listener(
        LoadBalancerArn=nlb_arn, Protocol="TCP", Port=443,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: elbv2.delete_listener(ListenerArn=nlb_listener),
                                   "ListenerNotFound"))

    link = apigw.create_vpc_link(
        name=ctx.unique_name("sim2real-vpclink-"), targetArns=[nlb_arn],
        description="sim2real private api via vpce", tags={"sim2real": CHECK},
    )
    link_id = link["id"]
    ctx.on_cleanup(lambda: _delete_vpc_link(apigw, link_id))

    private_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-private-"),
        endpointConfiguration={"types": ["PRIVATE"]}, tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore(lambda: apigw.delete_rest_api(restApiId=private_id),
                                   "NotFoundException"))
    root = next(i["id"] for i in apigw.get_resources(restApiId=private_id)["items"]
                if i["path"] == "/")
    who = apigw.create_resource(restApiId=private_id, parentId=root, pathPart="whoami")["id"]
    apigw.put_method(restApiId=private_id, resourceId=who, httpMethod="GET",
                     authorizationType="NONE")
    apigw.put_integration(restApiId=private_id, resourceId=who, httpMethod="GET", type="MOCK",
                          requestTemplates={"application/json": '{"statusCode": 200}'})
    apigw.put_method_response(restApiId=private_id, resourceId=who, httpMethod="GET",
                              statusCode="200")
    apigw.put_integration_response(
        restApiId=private_id, resourceId=who, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": json.dumps({"m": nonce})})
    _pin_policy(apigw, private_id, vpce_id)
    apigw.create_deployment(restApiId=private_id, stageName="s")

    # The regional front API's VPC_LINK integration is the in-VPC caller; the NLB targets are the
    # endpoint ENIs and the integration URI is the private API's hostname, which selects it.
    front_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-front-"),
        endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore(lambda: apigw.delete_rest_api(restApiId=front_id),
                                   "NotFoundException"))
    front_root = next(i["id"] for i in apigw.get_resources(restApiId=front_id)["items"]
                      if i["path"] == "/")
    apigw.put_method(restApiId=front_id, resourceId=front_root, httpMethod="GET",
                     authorizationType="NONE")
    apigw.put_integration(
        restApiId=front_id, resourceId=front_root, httpMethod="GET", type="HTTP_PROXY",
        integrationHttpMethod="GET", uri=f"{ctx.api_url(private_id, 's')}/whoami",
        connectionType="VPC_LINK", connectionId=link_id,
    )

    _poll(
        ctx, lambda: [t["TargetHealth"]["State"] for t in
                 elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]],
        lambda states: states == ["healthy", "healthy"],
        timeout_s=_budget_s(ctx, 600), interval_s=2, what="NLB targets (the endpoint ENIs) healthy",
    )
    status = _poll(ctx, lambda: apigw.get_vpc_link(vpcLinkId=link_id)["status"],
                   lambda s: s in ("AVAILABLE", "FAILED"),
                   timeout_s=_budget_s(ctx, 1200), interval_s=2, what="VpcLink AVAILABLE")
    assert status == "AVAILABLE", f"VpcLink ended {status!r}"
    apigw.create_deployment(restApiId=front_id, stageName="live")
    front_url = _invoke_url(ctx, front_id, "live") + "/"

    status, _, body = _poll(ctx, lambda: _http_get(front_url),
                            lambda r: r[0] == 200, timeout_s=_budget_s(ctx, 300), interval_s=2,
                            what="private API reached through its VPC endpoint")
    assert json.loads(body) == {"m": nonce}, f"in-VPC invoke returned {body!r}, expected the nonce"

    # Same path, policy re-pinned to an endpoint that is not ours.
    other = "vpce-" + ("0" * 17 if vpce_id != "vpce-" + "0" * 17 else "1" * 17)
    _pin_policy(apigw, private_id, other)
    apigw.create_deployment(restApiId=private_id, stageName="s")
    # A 5xx while the redeployed stage propagates is not the policy's answer; wait for a 4xx.
    status, _, body = _poll(ctx, lambda: _http_get(front_url),
                            lambda r: 400 <= r[0] < 500, timeout_s=_budget_s(ctx, 300), interval_s=2,
                            what="policy pinned to another endpoint taking effect")
    print(f"denied response: {status} {body[:400]!r}")
    assert status == 403, f"a non-matching aws:SourceVpce returned {status!r} {body!r}"
    assert nonce.encode() not in body, f"the nonce came through a denying policy: {body!r}"
    assert "not authorized to perform: execute-api:Invoke" in json.loads(body).get("Message", ""), (
        f"403 body does not name the policy denial: {body!r}"
    )

    # Restoring our endpoint id serves the nonce again.
    _pin_policy(apigw, private_id, vpce_id)
    apigw.create_deployment(restApiId=private_id, stageName="s")
    status, _, body = _poll(ctx, lambda: _http_get(front_url),
                            lambda r: r[0] == 200, timeout_s=_budget_s(ctx, 300), interval_s=2,
                            what="restored policy admitting our endpoint again")
    assert json.loads(body) == {"m": nonce}, f"restored path returned {body!r}"


def _pin_policy(apigw, api_id, vpce):
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke",
        "Resource": "execute-api:/*",
        "Condition": {"StringEquals": {"aws:SourceVpce": vpce}}}]}
    apigw.update_rest_api(restApiId=api_id, patchOperations=[
        {"op": "replace", "path": "/policy", "value": json.dumps(policy)}])


def _delete_vpce(ec2, vpce_id):
    ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        eps = ec2.describe_vpc_endpoints(
            Filters=[{"Name": "vpc-endpoint-id", "Values": [vpce_id]}])["VpcEndpoints"]
        if not eps or eps[0]["State"].lower() == "deleted":
            return
        time.sleep(2)
    raise RuntimeError(f"VPC endpoint {vpce_id} not deleted within 600s")


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
    """Wait for load-balancer ENIs to be released, then retry the delete on DependencyViolation:
    EC2 keeps reporting it for a while after the last ENI disappears."""
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
