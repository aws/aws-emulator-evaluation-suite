"""ecs-run-task-sync-resolves-task-token-into-container-env."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-run-task-sync-resolves-task-token-into-container-env"
GROUP = "sync_integration"
SERVICES = ["ecs", "stepfunctions"]

_CONTAINER_NAME = "worker"
_CONTAINERS = [{
    "name": _CONTAINER_NAME,
    "image": "public.ecr.aws/docker/library/busybox:1.36",
    "essential": True,
    "command": ["sh", "-c", "sleep 300"],
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
    cluster = ctx.unique_name("sim2real-xsvc-ecssfn-")
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
    family = ctx.unique_name("sim2real-xsvc-ecssfn-td-")
    td_arn = ecs.register_task_definition(
        family=family, containerDefinitions=_CONTAINERS, requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc", cpu="256", memory="512",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, td_arn))
    return td_arn


def _create_sfn_role(ctx, cluster_arn: str, td_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-ecssfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Description="sim2real-xsvc sfn ecs .sync execution role",
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
        {
            "Effect": "Allow",
            "Action": ["ecs:RunTask"],
            "Resource": td_arn,
            "Condition": {"ArnEquals": {"ecs:cluster": cluster_arn}},
        },
        {"Effect": "Allow", "Action": ["ecs:StopTask", "ecs:DescribeTasks"], "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": ["events:PutRule", "events:PutTargets", "events:DescribeRule"],
            "Resource": f"arn:aws:events:{ctx.region}:{ctx.account}:rule/"
                        "StepFunctionsGetEventsForECSTaskRule",
        },
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sfn-ecs-sync",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retries at first use
    # (_create_state_machine, _run_to_terminal) absorb it.
    return role_arn


def _create_state_machine(ctx, role_arn, cluster_arn, td_arn, subnet_id, sg_id):
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
                    "Overrides": {
                        "ContainerOverrides": [{
                            "Name": _CONTAINER_NAME,
                            "Environment": [{"Name": "TASK_TOKEN", "Value.$": "$$.Task.Token"}],
                        }]
                    },
                },
                "End": True,
            }
        },
    }
    name = ctx.unique_name("sim2real-xsvc-ecssfnsm-")
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


def _stop_task(ctx, cluster_arn, task_arn):
    ctx.client("ecs").stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real cleanup")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "AccessDeniedException",
)


def _run_until_task_scheduled(ctx, sm_arn, *, attempts=6):
    """Start the execution and return (exec_arn, history) once TaskScheduled appears.

    RunTask is the first runtime use of the fresh role; a failure whose cause names the role
    assumption or the denied action is the propagation race, and only that earns a retry.
    """
    desc = None
    for _ in range(attempts):
        exec_arn = _start(ctx, sm_arn)
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            events = _history(ctx, exec_arn)
            if any(e["type"] == "TaskScheduled" for e in events):
                return exec_arn, events
            desc = ctx.client("stepfunctions").describe_execution(executionArn=exec_arn)
            if desc["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
                break
            time.sleep(2)
        else:
            raise AssertionError(f"execution {exec_arn} never scheduled its ECS task within 60s")
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in blob for m in _PROPAGATION_MARKERS):
            raise AssertionError(
                f"execution ended {desc['status']!r} before scheduling its task: "
                f"{desc.get('error')!r} {desc.get('cause')!r}"
            )
        time.sleep(5)
    raise AssertionError(f"the role never propagated: {desc!r}")


_SUBMITTED_OR_TERMINAL = (
    "TaskSubmitted", "TaskSubmitFailed", "TaskFailed", "TaskTimedOut",
    "ExecutionSucceeded", "ExecutionFailed", "ExecutionAborted", "ExecutionTimedOut",
)


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """A Step Functions `ecs:runTask.sync` task resolves `$$.Task.Token` into the RunTask call
    it actually submits, and the ECS task ECS itself runs carries that token as the container's
    TASK_TOKEN environment variable, not the literal JSONPath string."""
    ecs = ctx.client("ecs")
    net = ctx.network()
    subnet_id = net.subnet_ids[0]

    cluster_arn = _create_cluster(ctx)
    td_arn = _create_task_definition(ctx)
    role_arn = _create_sfn_role(ctx, cluster_arn, td_arn)
    sm_arn = _create_state_machine(ctx, role_arn, cluster_arn, td_arn, subnet_id, net.security_group_id)

    exec_arn, events = _run_until_task_scheduled(ctx, sm_arn)
    scheduled = [e for e in events if e["type"] == "TaskScheduled"]
    assert len(scheduled) == 1, f"expected exactly one TaskScheduled event, got {scheduled!r}"
    sched = scheduled[0]["taskScheduledEventDetails"]
    assert (sched.get("resourceType"), sched.get("resource")) == ("ecs", "runTask.sync"), (
        f"TaskScheduled: expected resourceType/resource ('ecs', 'runTask.sync'), got {sched!r}"
    )
    resolved_params = json.loads(sched["parameters"])
    envs = resolved_params["Overrides"]["ContainerOverrides"][0]["Environment"]
    token_entries = [e for e in envs if e["Name"] == "TASK_TOKEN"]
    assert len(token_entries) == 1, (
        f"TaskScheduled's resolved parameters carry {envs!r} for the container env, "
        f"expected exactly one TASK_TOKEN entry"
    )
    token = token_entries[0]["Value"]
    assert token and token != "$$.Task.Token", (
        f"TASK_TOKEN was not resolved from the context object: {token!r}"
    )

    # Independent downstream read: the real ECS task ECS itself describes carries the same
    # resolved token as a container override, not merely what Step Functions claims it sent.
    # TaskSubmitted follows TaskScheduled once RunTask returns, so wait for it or for the
    # task or execution to end.
    events = _poll_until(
        lambda: _history(ctx, exec_arn),
        lambda evs: any(e["type"] in _SUBMITTED_OR_TERMINAL for e in evs),
        timeout_s=60.0,
    )
    submitted = [e for e in events if e["type"] == "TaskSubmitted"]
    assert len(submitted) == 1, f"expected exactly one TaskSubmitted event, got {submitted!r}"
    submitted_tasks = json.loads(submitted[0]["taskSubmittedEventDetails"]["output"])["Tasks"]
    assert len(submitted_tasks) == 1, f"RunTask submitted {submitted_tasks!r}, expected one task"
    task_arn = submitted_tasks[0]["TaskArn"]
    ctx.on_cleanup(lambda: _stop_task(ctx, cluster_arn, task_arn))

    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t.get("overrides", {}).get("containerOverrides"),
        timeout_s=60.0,
    )
    container_overrides = [o for o in task["overrides"]["containerOverrides"] if o["name"] == _CONTAINER_NAME]
    assert len(container_overrides) == 1, (
        f"DescribeTasks overrides carry {task['overrides']['containerOverrides']!r}, "
        f"expected one override for {_CONTAINER_NAME!r}"
    )
    ecs_envs = {e["name"]: e["value"] for e in container_overrides[0].get("environment", [])}
    assert ecs_envs.get("TASK_TOKEN") == token, (
        f"the real ECS task's TASK_TOKEN is {ecs_envs.get('TASK_TOKEN')!r}, the SFN-resolved "
        f"token was {token!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
