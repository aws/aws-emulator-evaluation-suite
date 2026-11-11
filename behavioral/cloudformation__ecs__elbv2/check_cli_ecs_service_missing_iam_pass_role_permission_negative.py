"""cli-ecs-service-missing-iam-pass-role-permission-negative."""
from __future__ import annotations

import json
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-ecs-service-missing-iam-pass-role-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A caller lacking `iam:PassRole` on the task execution role gets AccessDeniedException from
    RegisterTaskDefinition, so no task definition or target is ever created; a caller who can pass
    the role completes the identical load-balanced create-service workflow (positive control)."""
    iam = ctx.client("iam")
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    net = ctx.network()
    vpc_id, subnet_ids = net.vpc_id, net.subnet_ids[:2]
    alb_sg, task_sg = _create_alb_and_task_sgs(ctx, vpc_id)
    execution_role_arn = _create_ecs_execution_role(ctx)
    cluster = _create_cluster(ctx)

    alb_arn = _create_alb(ctx, vpc_id, subnet_ids, alb_sg, suffix="5")
    tg_arn = _create_target_group(ctx, vpc_id, suffix="5")
    _attach_listener(ctx, alb_arn, tg_arn, 80)
    _wait_alb_active(ctx, alb_arn)

    # A restricted caller that can perform ecs:* actions but is never granted iam:PassRole for
    # the execution role (or anything else) -- the sole missing permission under test.
    caller_role_name = ctx.unique_name("sim2real-caller-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=caller_role_name, AssumeRolePolicyDocument=json.dumps(trust))
    caller_role_arn = iam.get_role(RoleName=caller_role_name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=caller_role_name))
    iam.put_role_policy(
        RoleName=caller_role_name,
        PolicyName="ecs-only-no-passrole",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ecs:*", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName="ecs-only-no-passrole"))

    restricted_ecs = _assume_role_client(ctx, "ecs", caller_role_arn)

    family = ctx.unique_name("sim2real-pbtaskdef-")

    def _register_with_restricted_caller():
        restricted_ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            executionRoleArn=execution_role_arn,
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/nginx/nginx:1.27",
                    "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                    "essential": True,
                }
            ],
        )

    code, message = _error_code(_register_with_restricted_caller)
    assert code == "AccessDeniedException", f"expected AccessDeniedException for missing iam:PassRole, got {code}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{caller_role_name}/sim2real-negative-test "
        f"is not authorized to perform: iam:PassRole on resource: {execution_role_arn} "
        "because no identity-based policy allows the iam:PassRole action"
    )
    assert message == expected, f"RegisterTaskDefinition AccessDeniedException message: {message!r}"

    # effect absent: no task definition revision was ever created under this family
    listed = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert listed == [], f"expected no task definitions for {family}, found {listed}"

    # ... and, downstream, no target was ever registered in the target group either
    states = _target_states(ctx, tg_arn)
    assert states == [], f"expected no registered targets in {tg_arn}, found {states}"

    # positive control: an admin caller *can* pass the same role, and the resulting
    # load-balanced service does register a healthy target.
    task_def_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/nginx/nginx:1.27",
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def_arn))

    service_name = ctx.unique_name("sim2real-pbsvc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=1,
        launchType="FARGATE",
        loadBalancers=[{"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}],
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids,
                "securityGroups": [task_sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=service_name, force=True))

    healthy = _poll_until(
        lambda: [tid for tid, s in _target_states(ctx, tg_arn) if s == "healthy"],
        lambda v: len(v) == 1,
        timeout_s=300,
        interval_s=15,
    )
    assert len(healthy) == 1, f"expected exactly 1 healthy target in {tg_arn}, found {healthy}"


def _assume_role_client(ctx, service_name, role_arn, session_name="sim2real-negative-test"):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 60
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except ClientError as e:  # role trust propagation lag
            last_err = e
            time.sleep(5)
    if creds is None:
        raise AssertionError(f"could not assume {role_arn}: {last_err}")
    # Same target as ctx.client(); only the credentials differ for the restricted principal.
    return ctx.client(
        service_name,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


# ===== helpers =====


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


#: What a delete answers while a dependent drains: the force-deleted service's Fargate tasks hold
#: the cluster while they stop, and their ENIs and the ALB's hold the security groups.
_HELD = ("DependencyViolation", "ClusterContainsTasksException", "ClusterContainsServicesException")


def _retry_delete(fn, *, timeout_s=300.0):
    """Retry a delete while what holds the resource drains away; a resource already gone is done."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(("NotFound", "NotFoundException")):
                return
            if code not in _HELD or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _create_alb_and_task_sgs(ctx, vpc_id):
    ec2 = ctx.client("ec2")

    def _tags(name):
        return [{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}]

    alb_sg_name = ctx.unique_name("sim2real-albsg-")
    alb_sg = ec2.create_security_group(
        GroupName=alb_sg_name, Description="alb sg", VpcId=vpc_id, TagSpecifications=_tags(alb_sg_name)
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=alb_sg)))

    task_sg_name = ctx.unique_name("sim2real-tasksg-")
    task_sg = ec2.create_security_group(
        GroupName=task_sg_name, Description="task sg", VpcId=vpc_id, TagSpecifications=_tags(task_sg_name)
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=task_sg)))
    ec2.authorize_security_group_ingress(
        GroupId=task_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": alb_sg}]}],
    )
    return alb_sg, task_sg


def _create_ecs_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # No fixed sleep here: RegisterTaskDefinition does not validate assumability, and the
    # eventual task launch this role feeds is already covered by the bounded healthy-target
    # poll at the end of run() (deadline=300s), which absorbs any remaining IAM propagation lag.
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _retry_delete(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _short_name(ctx, prefix, max_len=32):
    name = ctx.unique_name(prefix)
    if len(name) <= max_len:
        return name
    return name[-max_len:].lstrip("-")


def _create_alb(ctx, vpc_id, subnet_ids, alb_sg_id, suffix=""):
    elbv2 = ctx.client("elbv2")
    alb_name = _short_name(ctx, f"sim2real-alb{suffix}-")
    lb = elbv2.create_load_balancer(
        Name=alb_name,
        Subnets=subnet_ids,
        SecurityGroups=[alb_sg_id],
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
    )["LoadBalancers"][0]
    alb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    return alb_arn


def _create_target_group(ctx, vpc_id, suffix="", port=80):
    elbv2 = ctx.client("elbv2")
    tg_name = _short_name(ctx, f"sim2real-tg{suffix}-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _attach_listener(ctx, alb_arn, tg_arn, port):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_alb_active(ctx, alb_arn, timeout_s=180):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(2)
    raise AssertionError(f"ALB {alb_arn} never became active, last state={state}")


def _target_states(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    return [(d["Target"]["Id"], d["TargetHealth"]["State"]) for d in descs]


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
