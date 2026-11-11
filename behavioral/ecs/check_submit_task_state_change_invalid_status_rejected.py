"""submit-task-state-change-invalid-status-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "submit-task-state-change-invalid-status-rejected"
GROUP = "ordering"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SubmitTaskStateChange with a non-enum status is refused with InvalidParameterException.

    A well-formed status on the same Fargate task is refused with a different code (AccessDenied).
    """
    ecs = ctx.client("ecs")
    cluster_name = _create_cluster(ctx)
    subnet_id, sg_id = _default_vpc_network(ctx)
    task_def_arn = _register_task_def(ctx, ctx.unique_name("sim2ordinv-td-"))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "DISABLED",
        }
    }
    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
    )
    assert run_resp["tasks"], f"RunTask produced no tasks: failures={run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_and_wait(ecs, cluster_name, task_arn))

    # Control: a well-formed status is also refused, but by the Fargate-agent-only gate with a
    # different code, so the enum refusal below is not a blanket denial.
    initial_status = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]["lastStatus"]
    control_error = control_message = None
    try:
        ecs.submit_task_state_change(cluster=cluster_name, task=task_arn, status=initial_status)
    except Exception as exc:  # noqa: BLE001
        control_error, control_message = _error_of(exc)
    assert control_error == "AccessDeniedException", (
        f"expected the well-formed control status {initial_status!r} to be refused with "
        f"AccessDeniedException (the Fargate-agent-only gate), got {control_error!r}"
    )
    assert control_message == "Fargate task state changes from the agent must have the instance verified", (
        f"unexpected AccessDeniedException message for the control status: {control_message!r}"
    )

    error_code = error_message = None
    try:
        ecs.submit_task_state_change(
            cluster=cluster_name, task=task_arn, status="NOT_A_REAL_ECS_TASK_STATUS"
        )
        raised = False
    except Exception as exc:  # noqa: BLE001
        raised = True
        error_code, error_message = _error_of(exc)

    assert raised, "SubmitTaskStateChange accepted a non-enum status value without error"
    assert error_code == "InvalidParameterException", (
        f"expected an InvalidParameterException, got {error_code}"
    )
    assert error_message == "The status NOT_A_REAL_ECS_TASK_STATUS is not a valid status.", (
        f"unexpected InvalidParameterException message for the non-enum status: {error_message!r}"
    )
    assert error_code != control_error, (
        "the non-enum status and the well-formed control status were rejected with the SAME "
        f"code ({error_code!r}) -- the enum value is not being validated on its own, this "
        "caller/task is just being denied outright"
    )


# ===== helpers =====


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2ordinv-cl-")
    ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))
    return cluster_name


def _default_vpc_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _register_task_def(ctx, family: str) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ECS_TAGS,
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _stop_and_wait(ecs, cluster_name: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_name, task=task_arn, reason="behavioral-check-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            task = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        if task["lastStatus"] == "STOPPED":
            return
        time.sleep(5.0)


def _error_of(exc: Any) -> tuple[str | None, str | None]:
    """(code, message) of a botocore ClientError; (None, None) for any other exception."""
    resp = getattr(exc, "response", None)
    if not resp:
        return None, None
    error = resp.get("Error", {})
    return error.get("Code"), error.get("Message")



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
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
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
