"""ecs-run-task-sync-without-run-task-permission-denied-and-no-task-created."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-run-task-sync-without-run-task-permission-denied-and-no-task-created"
GROUP = "sync_integration"
SERVICES = ["ecs", "stepfunctions"]

_CONTAINER_NAME = "worker"
_CONTAINERS = [{
    "name": _CONTAINER_NAME,
    "image": "public.ecr.aws/docker/library/busybox:1.36",
    "essential": True,
    "command": ["sh", "-c", "exit 0"],
}]

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
})


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-xsvc-ecssfnneg-")
    arn = ecs.create_cluster(
        clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(_teardown(lambda: ecs.delete_cluster(cluster=cluster), "ClusterNotFoundException"))
    return arn


def _delete_task_definition(ecs, arn: str) -> None:
    ecs.deregister_task_definition(taskDefinition=arn)
    ecs.delete_task_definitions(taskDefinitions=[arn])


def _create_task_definition(ctx):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-xsvc-ecssfnneg-td-")
    td_arn = ecs.register_task_definition(
        family=family, containerDefinitions=_CONTAINERS, requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc", cpu="256", memory="512",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, td_arn))
    return td_arn


def _create_sfn_role(ctx, cluster_arn: str, td_arn: str, *, grant_run_task: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-ecssfnnegrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Description="sim2real-xsvc sfn ecs .sync negative-permission role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {"Effect": "Allow", "Action": ["ecs:StopTask", "ecs:DescribeTasks"], "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": ["events:PutRule", "events:PutTargets", "events:DescribeRule"],
            "Resource": f"arn:aws:events:{ctx.region}:{ctx.account}:rule/"
                        "StepFunctionsGetEventsForECSTaskRule",
        },
    ]
    if grant_run_task:
        statements.append({
            "Effect": "Allow",
            "Action": ["ecs:RunTask"],
            "Resource": td_arn,
            "Condition": {"ArnEquals": {"ecs:cluster": cluster_arn}},
        })
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sfn-ecs-sync",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _create_state_machine(ctx, role_arn, cluster_arn, td_arn, subnet_id, sg_id, name_prefix):
    sfn = ctx.client("stepfunctions")
    definition = {
        "StartAt": "RunTask",
        "States": {
            "RunTask": {
                "Type": "Task",
                "Resource": "arn:aws:states:::ecs:runTask.sync",
                "Parameters": {
                    "Cluster": cluster_arn,
                    "TaskDefinition": td_arn,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": [subnet_id],
                            "SecurityGroups": [sg_id],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                },
                "End": True,
            }
        },
    }
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last_err}")


def _start(ctx, sm_arn):
    exec_arn = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-xsvc-exec-"), input="{}",
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=90.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


@tags("axis:rejection", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Step Functions role without ecs:RunTask on the task definition it names cannot start
    the ECS task its ecs:runTask.sync state submits; the identical definition under a role that
    does carry the permission succeeds, so the refusal is the one permission alone."""
    ecs = ctx.client("ecs")
    net = ctx.network()
    subnet_id = net.subnet_ids[0]

    cluster_arn = _create_cluster(ctx)
    td_arn = _create_task_definition(ctx)

    negative_role = _create_sfn_role(ctx, cluster_arn, td_arn, grant_run_task=False)
    negative_sm = _create_state_machine(
        ctx, negative_role, cluster_arn, td_arn, subnet_id, net.security_group_id,
        "sim2real-xsvc-ecssfnneg-sm-",
    )
    negative_exec = _start(ctx, negative_sm)
    negative_desc = _wait_terminal(ctx, negative_exec)
    assert negative_desc["status"] == "FAILED", (
        f"without ecs:RunTask, the execution ended {negative_desc['status']!r}, expected FAILED"
    )
    assert negative_desc.get("error") == "ECS.AccessDeniedException", (
        f"expected error 'ECS.AccessDeniedException', got {negative_desc.get('error')!r} "
        f"(cause {negative_desc.get('cause')!r})"
    )
    role_name = negative_role.rsplit("/", 1)[-1]
    cause = negative_desc.get("cause") or ""
    masked_cause = re.sub(r"Request ID: [^;)]+", "Request ID: <request-id>", cause)
    masked_cause = re.sub(
        rf"assumed-role/{re.escape(role_name)}/[A-Za-z0-9=,.@_-]+ is not",
        f"assumed-role/{role_name}/<session> is not", masked_cause)
    expected_cause = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized "
        f"to perform: ecs:RunTask on resource: {td_arn} because no identity-based policy "
        f"allows the ecs:RunTask action (Service: AmazonECS; Status Code: 400; Error Code: "
        f"AccessDeniedException; Request ID: <request-id>; Proxy: null)"
    )
    assert masked_cause == expected_cause, (
        f"the Cause must be ECS's exact AccessDeniedException for this role and task "
        f"definition; expected {expected_cause!r}, got {cause!r}"
    )
    tasks_after_denial = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert tasks_after_denial == [], (
        f"the denied RunTask still left task(s) in the cluster: {tasks_after_denial!r}"
    )

    positive_role = _create_sfn_role(ctx, cluster_arn, td_arn, grant_run_task=True)
    positive_sm = _create_state_machine(
        ctx, positive_role, cluster_arn, td_arn, subnet_id, net.security_group_id,
        "sim2real-xsvc-ecssfnpos-sm-",
    )
    positive_desc = _run_with_propagation_retry(ctx, positive_sm)
    assert positive_desc["status"] == "SUCCEEDED", (
        f"positive control (role carrying ecs:RunTask) ended {positive_desc['status']!r}: "
        f"{positive_desc.get('error')!r} {positive_desc.get('cause')!r}"
    )


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "AccessDeniedException",
)


def _run_with_propagation_retry(ctx, sm_arn, *, attempts=6):
    """Start the positive control, retrying only while the fresh role's grant is still
    propagating (the first runtime use of ecs:RunTask on this role)."""
    desc = None
    for _ in range(attempts):
        desc = _wait_terminal(ctx, _start(ctx, sm_arn))
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        time.sleep(5)
    return desc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
