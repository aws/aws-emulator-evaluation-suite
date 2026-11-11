"""create-service-load-balancer-missing-target-group-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-load-balancer-missing-target-group-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateService referencing a load balancer target group ARN that doesn't
    exist is rejected rather than creating a service with a dangling target
    group reference."""
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")
    vpc_id, subnet_id, sg_id, alb_subnet_ids = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-svclb-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "behavioral"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-svclb-td-")
    taskdef = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "web",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "command": ["sleep", "300"],
            }
        ],
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[taskdef]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=taskdef))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    account_id = sts.get_caller_identity()["Account"]
    missing_tg_name = ctx.unique_name("sim2real-missing-tg-")
    missing_tg_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        f"targetgroup/{missing_tg_name}/0123456789abcdef"
    )

    service_name = ctx.unique_name("sim2real-svclb-svc-")
    code, message = _error(
        lambda: ecs.create_service(
            cluster=cluster_arn,
            serviceName=service_name,
            taskDefinition=taskdef,
            desiredCount=0,
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            loadBalancers=[{"targetGroupArn": missing_tg_arn, "containerName": "web", "containerPort": 80}],
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected_message = f"The target group {missing_tg_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: an independent describe_services read reports the service
    # MISSING rather than merely omitting it from a list.
    described = ecs.describe_services(cluster=cluster_arn, services=[service_name])
    assert described["services"] == [], (
        f"a service leaked despite the missing target group: {described['services']!r}"
    )
    failures = described.get("failures", [])
    assert any(f.get("reason") == "MISSING" for f in failures), (
        f"expected a MISSING failure for {service_name!r}, got {failures!r}"
    )

    # Positive control: the identical request succeeds once it references a
    # target group that actually exists (only the ARN's existence changes;
    # everything else about the request is unchanged), proving the prior
    # rejection was specifically about the dangling reference and not some
    # other malformed part of the request.
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-svclb-tg-")[:32],
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    lb_name = ctx.unique_name("sim2real-svclb-")[:32]
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=alb_subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    import time as _t

    attempts, delay_s, last_err, resp = 10, 12, None, None
    for _ in range(attempts):
        try:
            resp = ecs.create_service(
                cluster=cluster_arn,
                serviceName=service_name,
                taskDefinition=taskdef,
                desiredCount=0,
                launchType="FARGATE",
                networkConfiguration=net_cfg,
                loadBalancers=[{"targetGroupArn": tg_arn, "containerName": "web", "containerPort": 80}],
                tags=[{"key": "sim2real", "value": "behavioral"}],
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterException":
                raise
            # A just-created target group/listener is not yet visible to ECS's
            # own validation everywhere; retry while that propagates.
            last_err = err.response["Error"].get("Message", str(err))
            _t.sleep(delay_s)
    if resp is None:
        raise AssertionError(last_err)
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    # Terminal read is independent of the create_service response that produced `resp`.
    described_good = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"]
    assert described_good, f"good service not visible via an independent describe_services: {service_name!r}"
    assert described_good[0]["loadBalancers"][0]["targetGroupArn"] == tg_arn, (
        f"expected targetGroupArn {tg_arn!r} via describe_services, got {described_good[0]['loadBalancers']!r}"
    )


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_target_group_when_free(elbv2, tg_arn, timeout_s=120):
    """Delete a target group, waiting while its load balancer's listener is still being torn down."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=tg_arn)
            return
        except ClientError as err:
            in_use = err.response["Error"]["Code"] == "ResourceInUse"
            if not in_use or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to create a service")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to create a service")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available to create a service")
    # An ALB requires subnets in >= 2 distinct AZs; the shared network normally has
    # one per AZ, so dedupe by AZ to get a set an ALB will accept.
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    alb_subnet_ids = list(by_az.values())[:2]
    if len(alb_subnet_ids) < 2:
        raise AssertionError("fewer than 2 AZs available for an ALB in the shared network")
    return vpc_id, subnets[0]["SubnetId"], sgs[0]["GroupId"], alb_subnet_ids



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
