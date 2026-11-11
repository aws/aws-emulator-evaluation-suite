"""elbv2-listener-rule-path-based-routing-to-multiple-ecs-services-positive."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "elbv2-listener-rule-path-based-routing-to-multiple-ecs-services-positive"
GROUP = "traffic-routing"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Two ECS services behind distinct target groups each receive traffic only for their path pattern."""
    net = _create_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)

    # The ALB never rewrites the request path, so each container must actually serve
    # content under the /svc-a or /svc-b directory the listener rule matches on --
    # serving only at "/" would 404 from Apache itself regardless of routing.
    td_a = _register_task_def(
        ctx,
        exec_role_arn,
        "web",
        "public.ecr.aws/docker/library/httpd:2.4",
        80,
        command=[
            "sh",
            "-c",
            "mkdir -p /usr/local/apache2/htdocs/svc-a && "
            "cp /usr/local/apache2/htdocs/index.html /usr/local/apache2/htdocs/svc-a/index.html && "
            "httpd-foreground",
        ],
    )
    td_b = _register_task_def(
        ctx,
        exec_role_arn,
        "web",
        "public.ecr.aws/docker/library/httpd:2.4",
        80,
        command=[
            "sh",
            "-c",
            "mkdir -p /usr/local/apache2/htdocs/svc-b && "
            "echo sim2real-hello-from-b > /usr/local/apache2/htdocs/svc-b/index.html && "
            "httpd-foreground",
        ],
    )

    alb = _create_alb(ctx, net["subnet_ids"], net["alb_sg"])
    # A zero deregistration delay keeps teardown (ECS task stop -> ALB target
    # drain -> cluster delete) inside the harness's cleanup budget; this check's
    # subject is path routing, not drain timing.
    tg_a = _create_target_group(ctx, net["vpc_id"], deregistration_delay=0)
    tg_b = _create_target_group(ctx, net["vpc_id"], deregistration_delay=0)

    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb["arn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": "404",
                    "ContentType": "text/plain",
                    "MessageBody": "no-match",
                },
            }
        ],
        Tags=[_TAG_EC2],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/svc-a*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_a}],
    )
    elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=20,
        Conditions=[{"Field": "path-pattern", "Values": ["/svc-b*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_b}],
    )

    svc_a = _create_service(
        ctx,
        cluster_arn,
        td_a,
        net["subnet_ids"],
        net["task_sg"],
        desired_count=1,
        tg_arn=tg_a,
        container_name="web",
        container_port=80,
    )
    svc_b = _create_service(
        ctx,
        cluster_arn,
        td_b,
        net["subnet_ids"],
        net["task_sg"],
        desired_count=1,
        tg_arn=tg_b,
        container_name="web",
        container_port=80,
    )
    _wait_service_stable(ctx, cluster_arn, svc_a["name"])
    _wait_service_stable(ctx, cluster_arn, svc_b["name"])

    _poll_until(
        lambda: _target_health(ctx, tg_a),
        lambda ds: len(ds) == 1 and ds[0]["TargetHealth"]["State"] == "healthy",
        timeout_s=120,
        interval_s=5,
    )
    _poll_until(
        lambda: _target_health(ctx, tg_b),
        lambda ds: len(ds) == 1 and ds[0]["TargetHealth"]["State"] == "healthy",
        timeout_s=120,
        interval_s=5,
    )

    body_a = _poll_http_body(ctx, f"http://{alb['dns']}/svc-a/", timeout_s=180)
    body_b = _poll_http_body(ctx, f"http://{alb['dns']}/svc-b/", timeout_s=180)
    body_default = _poll_http_body(
        ctx, f"http://{alb['dns']}/no-such-path", timeout_s=90, expect_status=404
    )

    assert "It works" in body_a, f"unexpected body routed to /svc-a*: {body_a!r}"
    assert "sim2real-hello-from-b" in body_b, (
        f"unexpected body routed to /svc-b*: {body_b!r}"
    )
    assert "sim2real-hello-from-b" not in body_a, (
        f"svc-b's body leaked into /svc-a* response: {body_a!r}"
    )
    assert "It works" not in body_b, (
        f"svc-a's body leaked into /svc-b* response: {body_b!r}"
    )
    assert "no-match" in body_default, (
        f"unmatched path did not hit the default fixed-response action: {body_default!r}"
    )


def _poll_http_body(ctx, url, timeout_s=90.0, interval_s=5.0, expect_status=200):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=5) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == expect_status:
                return e.read().decode("utf-8", "replace")
            last_err = e
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:  # DNS/connection during ALB warmup
            last_err = e
        time.sleep(interval_s)
    raise AssertionError(
        f"never got a usable HTTP response from {url} within {timeout_s}s: {last_err!r}"
    )


_PREFIX = "sim2real-ecsalb-"
_TAG_EC2 = {"Key": "sim2real:managed", "Value": "true"}
_TAG_ECS = {"key": "sim2real:managed", "value": "true"}


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_when_free(fn, timeout_s=600.0, interval_s=10.0):
    """Teardown: retry a VPC-scoped delete while AWS still reports a dependency. Fargate task and
    load-balancer ENIs are released asynchronously after their owners are deleted."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("DependencyViolation", "ResourceInUse") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _ec2_tags(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name},
                                                      {"Key": "sim2real:managed", "Value": "true"}]}]


def _owned_vpc(ctx, ec2, cidr):
    """A VPC the check creates: two public subnets in two AZs, routed to an internet gateway."""
    import ipaddress

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_ec2_tags("vpc", _name(ctx, "vpc")))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags("internet-gateway", _name(ctx, "igw")))[
        "InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_when_free(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_ec2_tags("route-table", _name(ctx, "rtb")))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"an ALB needs two availability zones; {ctx.region} offers {zones!r}"
    halves = list(ipaddress.ip_network(cidr).subnets(prefixlen_diff=1))
    subnet_ids = []
    for zone, block in zip(zones[:2], halves):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=str(block), AvailabilityZone=zone,
            TagSpecifications=_ec2_tags("subnet", _name(ctx, "subnet")))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _delete_when_free(lambda: ec2.delete_subnet(SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc_id: ec2.disassociate_route_table(AssociationId=a))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _owned_vpc(ctx, ec2, "10.182.0.0/24")

    def _sg(description, peer):
        sg_id = ec2.create_security_group(
            GroupName=_name(ctx, "sg"),
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": [_TAG_EC2]}],
        )["GroupId"]
        ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_security_group(GroupId=sg_id)))
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, **peer}],
        )
        return sg_id

    # The ALB admits the runner on tcp/80; the tasks admit tcp/80 only from the ALB's group.
    alb_sg = _sg("sim2real ecs-alb load balancer sg", {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    task_sg = _sg("sim2real ecs-alb task sg", {"UserIdGroupPairs": [{"GroupId": alb_sg}]})
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "alb_sg": alb_sg, "task_sg": task_sg}


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = _name(ctx, "exec-role")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[_TAG_EC2],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    # IAM propagation to ECS/Fargate is absorbed by _wait_service_stable's bounded
    # retry (up to 420s) once the service tries to launch tasks with this role.
    return role_arn


def _delete_cluster_when_empty(ecs, cluster_arn, timeout_s=600.0, interval_s=10.0):
    """Teardown: a cluster refuses deletion while its tasks are still stopping, so wait them out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ClusterContainsTasksException", "ClusterContainsServicesException") or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(interval_s)


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(
        clusterName=_name(ctx, "cluster"),
        tags=[_TAG_ECS],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, arn))
    return arn


def _register_task_def(
    ctx, exec_role_arn, container_name, image, container_port, command=None
):
    ecs = ctx.client("ecs")
    container = {
        "name": container_name,
        "image": image,
        "essential": True,
        "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=_name(ctx, "taskdef"),
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
        tags=[_TAG_ECS],
    )
    td_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, td_arn))
    return td_arn


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_load_balancer(
        Name=_name(ctx, "alb"),
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
        Tags=[_TAG_EC2],
    )
    alb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    alb_dns = resp["LoadBalancers"][0]["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])[
            "LoadBalancers"
        ][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=240,
        interval_s=10,
    )
    return {"arn": alb_arn, "dns": alb_dns}


def _create_target_group(
    ctx,
    vpc_id,
    port=80,
    target_type="ip",
    health_check_path="/",
    interval=10,
    healthy_threshold=2,
    unhealthy_threshold=2,
    deregistration_delay=None,
):
    elbv2 = ctx.client("elbv2")
    timeout = max(2, min(interval - 1, 5))
    tg_arn = elbv2.create_target_group(
        Name=_name(ctx, "tg"),
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType=target_type,
        HealthCheckProtocol="HTTP",
        HealthCheckPath=health_check_path,
        HealthCheckIntervalSeconds=interval,
        HealthCheckTimeoutSeconds=timeout,
        HealthyThresholdCount=healthy_threshold,
        UnhealthyThresholdCount=unhealthy_threshold,
        Tags=[_TAG_EC2],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    if deregistration_delay is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[
                {
                    "Key": "deregistration_delay.timeout_seconds",
                    "Value": str(deregistration_delay),
                }
            ],
        )
    return tg_arn


def _create_service(
    ctx,
    cluster_arn,
    task_def_arn,
    subnet_ids,
    sg_id,
    desired_count=1,
    tg_arn=None,
    container_name=None,
    container_port=None,
    grace_period=None,
):
    ecs = ctx.client("ecs")
    name = _name(ctx, "svc")
    kwargs = dict(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids,
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[_TAG_ECS],
    )
    if tg_arn:
        kwargs["loadBalancers"] = [
            {
                "targetGroupArn": tg_arn,
                "containerName": container_name,
                "containerPort": container_port,
            }
        ]
    if grace_period is not None:
        kwargs["healthCheckGracePeriodSeconds"] = grace_period
    svc_arn = ecs.create_service(**kwargs)["service"]["serviceArn"]

    def _cleanup():
        try:
            ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        try:
            ecs.delete_service(cluster=cluster_arn, service=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": svc_arn, "name": name}


def _wait_service_stable(ctx, cluster_arn, service_name, timeout_s=420):
    ecs = ctx.client("ecs")
    waiter = ecs.get_waiter("services_stable")
    waiter.wait(
        cluster=cluster_arn,
        services=[service_name],
        WaiterConfig={"Delay": 2, "MaxAttempts": max(1, timeout_s // 2)},
    )


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
