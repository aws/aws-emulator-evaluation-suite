"""ecs-task-launch-fails-without-ecs-tasks-trust."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-task-launch-fails-without-ecs-tasks-trust"
GROUP = "iam-trust"
SERVICES = ["ecr", "ecs", "elbv2"]

_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"
_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task whose execution role trusts ec2.amazonaws.com rather than ecs-tasks.amazonaws.com
    never reaches RUNNING because the Fargate agent cannot assume it, while an identical task
    using a correctly trusted role (the positive control) does."""
    subnet_id, sg_id = _default_network(ctx)
    cluster = _create_cluster(ctx)

    good_role_arn = _create_execution_role(ctx, trust_service="ecs-tasks.amazonaws.com")
    bad_role_arn = _create_execution_role(ctx, trust_service="ec2.amazonaws.com")

    good_td, _good_family = _register_task_def(ctx, good_role_arn)
    bad_td, bad_family = _register_task_def(ctx, bad_role_arn)

    ecs = ctx.client("ecs")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    good_run = _run_task_with_retry(ecs, cluster, good_td, net_cfg)
    assert not good_run.get("failures"), f"RunTask reported failures for the control task: {good_run.get('failures')}"
    good_task_arn = good_run["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda t=good_task_arn: _stop_task_quietly(ctx, cluster, t))

    bad_outcome = _run_task_expect_rejection(ctx, ecs, cluster, bad_td, net_cfg)

    good_task = _wait_for_task_terminal(ctx, cluster, good_task_arn, timeout_s=240.0)
    assert good_task["lastStatus"] == "RUNNING", (
        "positive control: a task using a correctly-trusted execution role did not reach "
        f"RUNNING: lastStatus={good_task['lastStatus']} stoppedReason={good_task.get('stoppedReason')}"
    )

    if bad_outcome["kind"] == "rejected":
        reason = bad_outcome["message"]
        assert "assume" in reason.lower(), (
            f"RunTask rejected the broken-trust role but not for an assume-role reason: {reason}"
        )
        code = bad_outcome.get("code")
        if code is not None:
            assert code == "ClientException", (
                f"expected RunTask to reject the untrusted execution role with ClientException, "
                f"got code={code!r}: {reason}"
            )
            expected = (
                f"ECS was unable to assume the role '{bad_role_arn}' that was provided for this task. "
                "Please verify that the role being passed has the proper trust relationship and "
                "permissions and that your IAM user has permissions to pass this role."
            )
            assert reason == expected, f"RunTask rejected the untrusted execution role with {reason!r}"
        listed = ecs.list_tasks(cluster=cluster, family=bad_family)["taskArns"]
        assert listed == [], (
            f"RunTask rejected the broken-trust role but a task still exists for it: {listed}"
        )
    else:
        bad_task_arn = bad_outcome["task_arn"]
        ctx.on_cleanup(lambda t=bad_task_arn: _stop_task_quietly(ctx, cluster, t))
        bad_task = _wait_for_task_terminal(ctx, cluster, bad_task_arn, timeout_s=240.0)
        assert bad_task["lastStatus"] == "STOPPED", (
            "a task using an execution role that does NOT trust ecs-tasks.amazonaws.com "
            f"reached lastStatus={bad_task['lastStatus']} -- it must never reach RUNNING"
        )
        reason = bad_task.get("stoppedReason") or ""
        assert "assume" in reason.lower(), (
            "a task using an execution role that does NOT trust ecs-tasks.amazonaws.com stopped, "
            f"but its stoppedReason does not name an assume-role failure: {reason!r}"
        )


# ===== helpers =====


def _default_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to launch a Fargate task in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "map-public-ip-on-launch", "Values": ["true"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch a Fargate task in")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_execution_role(ctx, trust_service: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda r=role_name: _delete_role(ctx, r))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    _wait_role_visible(ctx, role_name)
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _wait_role_visible(ctx, role_name: str, timeout_s: float = 30.0) -> None:
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(2.0)
    raise AssertionError(f"role {role_name} never became visible via GetRole")


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda c=name: _delete_cluster_quietly(ctx, c))
    return name


def _delete_cluster_quietly(ctx, cluster: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster)


def _register_task_def(ctx, execution_role_arn: str, image: str = _IMAGE) -> tuple[str, str]:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-task-")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {"name": "app", "image": image, "essential": True, "command": ["sleep", "300"]}
        ],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda t=task_def_arn: _retire_task_definition(ecs, t))
    return task_def_arn, family


def _wait_for_task_terminal(
    ctx, cluster: str, task_arn: str, timeout_s: float = 240.0, interval_s: float = 5.0
) -> dict[str, Any]:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks:
            last = tasks[0]
            if last["lastStatus"] in ("RUNNING", "STOPPED"):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"task {task_arn} never reached RUNNING/STOPPED within {timeout_s}s (last={last})")


def _run_task_with_retry(
    ecs, cluster: str, task_def_arn: str, net_cfg: dict, timeout_s: float = 90.0, interval_s: float = 5.0
) -> dict[str, Any]:
    """RunTask synchronously calls sts:AssumeRole on the execution role before it will launch
    a task. A role that was JUST created (and just had a policy attached) is often not yet
    visible to that synchronous check even though GetRole already returns it -- IAM trust/policy
    propagation lags role creation. Retry on that specific ClientException instead of treating it
    as a hard failure."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
        except Exception as e:  # noqa: BLE001 - inspect message, then re-raise if unrelated
            if "unable to assume the role" in str(e).lower():
                last_err = e
                time.sleep(interval_s)
                continue
            raise
        if resp.get("failures"):
            last_err = AssertionError(f"RunTask reported failures: {resp['failures']}")
            time.sleep(interval_s)
            continue
        return resp
    raise AssertionError(f"RunTask never succeeded within {timeout_s}s (last error: {last_err})")


def _run_task_expect_rejection(
    ctx, ecs, cluster: str, task_def_arn: str, net_cfg: dict, timeout_s: float = 60.0, interval_s: float = 5.0
) -> dict[str, Any]:
    """A role whose trust policy does NOT include ecs-tasks.amazonaws.com should be rejected by
    RunTask's synchronous AssumeRole check every single time -- unlike the transient propagation
    delay a brand-new *correctly*-trusted role can hit, this is a permanent trust mismatch, so we
    do not expect it to ever start succeeding. Poll for a bounded window anyway (belt-and-braces
    against a slow-to-materialize rejection) and return either the rejection message or, if AWS
    unexpectedly let the task launch, the task ARN so the caller can check its terminal state."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
        except ClientError as e:  # noqa: BLE001 - this is the expected rejection path
            msg = str(e)
            if "unable to assume the role" in msg.lower() or "assume" in msg.lower():
                return {"kind": "rejected", "message": e.response["Error"].get("Message", msg),
                        "code": e.response["Error"]["Code"]}
            raise
        if resp.get("failures"):
            return {"kind": "rejected", "message": str(resp["failures"]), "code": None}
        return {"kind": "task", "task_arn": resp["tasks"][0]["taskArn"]}
    raise AssertionError(f"RunTask for the broken-trust role never resolved within {timeout_s}s")


def _stop_task_quietly(ctx, cluster: str, task_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real check cleanup")
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ClusterNotFoundException":
            return
        if not (err["Code"] == "InvalidParameterException" and "not found" in err.get("Message", "").lower()):
            raise
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
            tasks = resp.get("tasks", [])
            if not tasks or tasks[0]["lastStatus"] == "STOPPED":
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        time.sleep(2.0)
    raise AssertionError(f"task {task_arn} in {cluster} not STOPPED within 180s of StopTask")



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
            except ClientError:
                pass
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError:
                pass
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
            aws_code = e.response["Error"]["Code"]
            if aws_code == "ClusterNotFoundException":
                return
            if aws_code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif aws_code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
