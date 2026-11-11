"""cli-ecs-task-log-delivery-blocked-without-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cli-ecs-task-log-delivery-blocked-without-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fargate task whose execution role lacks logs:CreateLogStream/PutLogEvents stops with
    ResourceInitializationError and delivers no log stream, while a role with those permissions
    delivers; attaching the policy to the same role makes the same task definition deliver."""
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    check_tag = [{"key": "sim2real-check", "value": CHECK}]
    cluster_name = ctx.unique_name("sim2real-cluster-")
    subnet_id, sg_id = _check_subnet_and_sg(ctx)
    ecs.create_cluster(clusterName=cluster_name, tags=check_tag)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    public_image = "public.ecr.aws/docker/library/busybox:1.36"
    good_marker = ctx.unique_name("sim2real-good-marker-")
    bad_marker = ctx.unique_name("sim2real-bad-marker-")
    good_log_group = "/sim2real/" + ctx.unique_name("perm-good-")
    bad_log_group = "/sim2real/" + ctx.unique_name("perm-bad-")
    logs.create_log_group(logGroupName=good_log_group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=good_log_group))
    logs.create_log_group(logGroupName=bad_log_group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=bad_log_group))

    good_role_arn = _create_role(ctx, ctx.unique_name("sim2real-good-role-"), attach_logs_policy=True)
    bad_role_name = ctx.unique_name("sim2real-bad-role-")
    bad_role_arn = _create_role(ctx, bad_role_name, attach_logs_policy=False)

    # ---- positive control: role WITH logs permissions delivers logs normally ----
    good_task_def_arn = _register_task_def(
        ctx, ecs, ctx.unique_name("sim2real-taskdef-good-"), good_role_arn, public_image,
        good_log_group, good_marker,
    )
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, good_task_def_arn))
    good_task_arn = _run_task_with_role_retry(ctx, ecs, cluster_name, good_task_def_arn, subnet_id, sg_id, 90.0)
    _poll_until(
        lambda: (ecs.describe_tasks(cluster=cluster_name, tasks=[good_task_arn])["tasks"] or [None])[0],
        lambda t: t is not None and t.get("lastStatus") == "STOPPED",
        timeout_s=300.0, interval_s=2.0,
    )
    good_events = _poll_until(
        lambda: logs.filter_log_events(logGroupName=good_log_group)["events"],
        lambda evs: any(good_marker in e["message"] for e in evs),
        timeout_s=180.0, interval_s=2.0,
    )
    assert any(good_marker in e["message"] for e in good_events), "positive control failed to deliver logs"

    # ---- negative: role WITHOUT logs permissions never delivers logs ----
    bad_task_def_arn = _register_task_def(
        ctx, ecs, ctx.unique_name("sim2real-taskdef-bad-"), bad_role_arn, public_image,
        bad_log_group, bad_marker,
    )
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, bad_task_def_arn))
    bad_task_arn = _run_task_with_role_retry(ctx, ecs, cluster_name, bad_task_def_arn, subnet_id, sg_id, 90.0)
    bad_task_detail = _poll_until(
        lambda: (ecs.describe_tasks(cluster=cluster_name, tasks=[bad_task_arn])["tasks"] or [None])[0],
        lambda t: t is not None and t.get("lastStatus") == "STOPPED",
        timeout_s=300.0, interval_s=2.0,
    )
    stopped_reason = bad_task_detail.get("stoppedReason", "")
    assert "ResourceInitializationError" in stopped_reason, (
        f"expected ResourceInitializationError due to missing logs permission, got: {stopped_reason!r}"
    )

    # The task has stopped, so the stream it could not create is absent now; the restore leg's
    # delivery below is the positive control ordered after it.
    streams = logs.describe_log_streams(logGroupName=bad_log_group).get("logStreams", [])
    assert streams == [], f"expected no log streams without permission, found: {streams!r}"
    bad_events = logs.filter_log_events(logGroupName=bad_log_group).get("events", [])
    assert bad_events == [], f"expected zero delivered log events without permission, found: {bad_events!r}"
    bad_stream = f"ecs/app/{bad_task_arn.rsplit('/', 1)[-1]}"

    # ---- restore: attach the missing permission to the SAME role, and re-run the SAME task
    # definition, proving the missing permission (and nothing else) was the cause ----
    logs_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=bad_role_name, PolicyArn=logs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=bad_role_name, PolicyArn=logs_policy_arn))

    # Bounded retry, not an unconditional sleep: a just-attached IAM policy can lag behind the
    # ECS agent's own view of the role for a short window, which would otherwise be
    # indistinguishable from the permission still being missing.
    restore_deadline = time.monotonic() + 180.0
    restored_events = None
    last_restore_reason = None
    while time.monotonic() < restore_deadline and restored_events is None:
        restored_task_arn = _run_task_with_role_retry(ctx, ecs, cluster_name, bad_task_def_arn, subnet_id, sg_id, 90.0)
        restored_detail = _poll_until(
            lambda: (ecs.describe_tasks(cluster=cluster_name, tasks=[restored_task_arn])["tasks"] or [None])[0],
            lambda t: t is not None and t.get("lastStatus") == "STOPPED",
            timeout_s=300.0, interval_s=2.0,
        )
        last_restore_reason = restored_detail.get("stoppedReason", "")
        if "ResourceInitializationError" in last_restore_reason:
            time.sleep(2)
            continue
        restored_events = _poll_until(
            lambda: logs.filter_log_events(logGroupName=bad_log_group)["events"],
            lambda evs: any(bad_marker in e["message"] for e in evs),
            timeout_s=180.0, interval_s=2.0,
        )
        break
    assert restored_events is not None and any(bad_marker in e["message"] for e in restored_events), (
        f"attaching the logs policy to the identical role and re-running the identical task "
        f"definition must restore log delivery; last stopped reason: {last_restore_reason!r}"
    )
    late = [e for e in restored_events if e.get("logStreamName") == bad_stream]
    assert late == [], f"the denied task delivered log events once a later task did: {late!r}"


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last}")


def _create_role(ctx, role_name: str, *, attach_logs_policy: bool) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if attach_logs_policy:
        policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # else: deliberately no permission policy at all — trust-only role, cannot call any AWS API
    _poll_until(
        lambda: iam.get_role(RoleName=role_name),
        lambda resp: resp["Role"]["Arn"] == role_arn,
        timeout_s=20.0, interval_s=2.0,
    )
    return role_arn


def _register_task_def(ctx, ecs, family, role_arn, image, log_group, marker) -> str:
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
        containerDefinitions=[
            {
                "name": "app",
                "image": image,
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; sleep 3"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "ecs",
                    },
                },
            }
        ],
    )
    return resp["taskDefinition"]["taskDefinitionArn"]


def _check_subnet_and_sg(ctx):
    net = _create_network(ctx, n_subnets=1)
    return net["subnet_id"], net["sg_id"]


def _create_network(ctx, n_subnets: int = 1) -> dict:
    """A VPC this check owns: public subnets behind an internet gateway (Fargate pulls the image
    over a public IP) and a security group with only the default allow-all egress rule. One
    cleanup tears the whole network down in dependency order, retrying while ECS still holds
    task ENIs in it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-net-")

    def tag(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]

    net: dict = {"subnet_ids": []}
    net["vpc_id"] = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=tag("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ctx, net))
    ec2.get_waiter("vpc_available").wait(VpcIds=[net["vpc_id"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    net["igw_id"] = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    net["igw_attached"] = True
    net["rt_id"] = ec2.create_route_table(VpcId=net["vpc_id"], TagSpecifications=tag("route-table"))[
        "RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt_id"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw_id"])
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]]
    if len(zones) < n_subnets:
        raise AssertionError(f"need {n_subnets} availability zones, the region offers {zones}")
    for i, zone in enumerate(sorted(zones)[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=net["vpc_id"], CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=zone, TagSpecifications=tag("subnet")
        )["Subnet"]["SubnetId"]
        net["subnet_ids"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=net["rt_id"], SubnetId=subnet_id)
    net["subnet_id"] = net["subnet_ids"][0]
    net["sg_id"] = ec2.create_security_group(
        GroupName=name, Description="sim2real check network", VpcId=net["vpc_id"], TagSpecifications=tag("security-group")
    )["GroupId"]
    return net


def _delete_network(ctx, net: dict, timeout_s: float = 900.0) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s

    def retrying(fn, **kwargs):
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                    return
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
            time.sleep(15)

    if net.get("sg_id"):
        retrying(ec2.delete_security_group, GroupId=net["sg_id"])
    for subnet_id in net["subnet_ids"]:
        retrying(ec2.delete_subnet, SubnetId=subnet_id)
    if net.get("rt_id"):
        retrying(ec2.delete_route_table, RouteTableId=net["rt_id"])
    if net.get("igw_attached"):
        retrying(ec2.detach_internet_gateway, InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    if net.get("igw_id"):
        retrying(ec2.delete_internet_gateway, InternetGatewayId=net["igw_id"])
    retrying(ec2.delete_vpc, VpcId=net["vpc_id"])


def _run_task_with_role_retry(ctx, ecs, cluster_name, task_def_arn, subnet_id, sg_id, timeout_s: float) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
                count=1,
            )
            failures = resp.get("failures", [])
            if failures:
                last_error = failures
                time.sleep(5.0)
                continue
            return resp["tasks"][0]["taskArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("InvalidParameterException", "ClientException") and "assume" in message.lower():
                last_error = message
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"run_task never succeeded within {timeout_s}s; last error: {last_error}")


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
