"""e2e-maintenance-window-execution-history-flow."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-maintenance-window-execution-history-flow"
GROUP = "e2e"
SERVICES = ["ssm"]

_INSTANCE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A per-minute maintenance window execution appears in the Describe/Get execution APIs, stays
    queryable after DeleteMaintenanceWindow; a Safe deregister of a target still referenced by a
    task is rejected until the task is removed."""
    ssm = ctx.client("ssm")
    instance_id = _create_ssm_managed_instance(ctx)
    window_name = ctx.unique_name("sim2real-mw-")

    window_id = ssm.create_maintenance_window(
        Name=window_name,
        Schedule="cron(0/1 * * * ? *)",
        ScheduleTimezone="UTC",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=False,
    )["WindowId"]
    ctx.on_cleanup(lambda: _ignore(ssm.delete_maintenance_window, WindowId=window_id))

    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": [instance_id]}],
    )["WindowTargetId"]

    task_id = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        Targets=[{"Key": "WindowTargetIds", "Values": [target_id]}],
        TaskInvocationParameters={"RunCommand": {"Parameters": {"commands": ["echo hi"]}}},
        MaxConcurrency="1",
        MaxErrors="1",
        Priority=1,
    )["WindowTaskId"]

    # Negative: the target is still referenced by the task, so a "safe" deregister is
    # rejected and the target remains registered.
    in_use = _error(
        lambda: ssm.deregister_target_from_maintenance_window(
            WindowId=window_id, WindowTargetId=target_id, Safe=True
        )
    )
    assert in_use["Code"] == "TargetInUseException", f"expected TargetInUseException, got {in_use!r}"
    assert in_use["Message"] == (
        f"This Target cannot be deregistered because it is still referenced in Task: {task_id}"
    ), in_use["Message"]
    still_there = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert any(t["WindowTargetId"] == target_id for t in still_there), (
        f"target {target_id} missing from {still_there!r} after a rejected deregister"
    )

    # Wait for the per-minute cron schedule to fire and produce an execution record.
    executions = _poll_until(
        lambda: ssm.describe_maintenance_window_executions(WindowId=window_id)["WindowExecutions"],
        lambda execs: len(execs) >= 1,
        timeout_s=200.0,
        interval_s=10.0,
    )
    assert len(executions) >= 1, f"cron never produced an execution: {executions!r}"
    window_execution_id = executions[0]["WindowExecutionId"]

    # GetMaintenanceWindowExecutionTask/DescribeMaintenanceWindowExecutionTaskInvocations key on
    # the execution's own TaskExecutionId (minted per firing), not the static WindowTaskId from
    # registration -- DescribeMaintenanceWindowExecutionTasks is where that id is surfaced.
    exec_tasks = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_tasks(
            WindowExecutionId=window_execution_id
        )["WindowExecutionTaskIdentities"],
        lambda tasks: any(t["TaskArn"] == "AWS-RunShellScript" for t in tasks),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert any(t["TaskArn"] == "AWS-RunShellScript" for t in exec_tasks), (
        f"no AWS-RunShellScript task under execution {window_execution_id}: {exec_tasks!r}"
    )
    task_execution_id = next(
        t["TaskExecutionId"] for t in exec_tasks if t["TaskArn"] == "AWS-RunShellScript"
    )

    task_exec = ssm.get_maintenance_window_execution_task(
        WindowExecutionId=window_execution_id, TaskId=task_execution_id
    )
    assert task_exec["TaskArn"] == "AWS-RunShellScript", task_exec["TaskArn"]

    invocations = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=window_execution_id, TaskId=task_execution_id
        )["WindowExecutionTaskInvocationIdentities"],
        lambda invs: len(invs) >= 1,
        timeout_s=150.0,
        interval_s=10.0,
    )
    assert len(invocations) >= 1, f"no invocation recorded for task execution {task_execution_id}"
    invocation = invocations[0]
    assert invocation["TaskExecutionId"] == task_execution_id, invocation
    assert invocation["WindowExecutionId"] == window_execution_id, invocation

    # Positive control: remove the task first, then the target deregisters cleanly.
    ssm.deregister_task_from_maintenance_window(WindowId=window_id, WindowTaskId=task_id)
    ssm.deregister_target_from_maintenance_window(
        WindowId=window_id, WindowTargetId=target_id, Safe=True
    )

    ssm.delete_maintenance_window(WindowId=window_id)

    # The window itself is gone ...
    gone = _error(lambda: ssm.get_maintenance_window(WindowId=window_id))
    assert gone["Code"] == "DoesNotExistException", f"expected DoesNotExistException, got {gone!r}"
    assert gone["Message"] == f"Maintenance window {window_id} does not exist", gone["Message"]

    # ... but execution history survives deletion of the window itself.
    after_delete = ssm.describe_maintenance_window_executions(WindowId=window_id)[
        "WindowExecutions"
    ]
    assert len(after_delete) >= 1, f"execution history vanished after window delete: {after_delete!r}"
    assert any(e["WindowExecutionId"] == window_execution_id for e in after_delete), (
        f"execution {window_execution_id} missing from post-delete history {after_delete!r}"
    )


def _error(fn: Any) -> dict:
    """Call fn() and return its botocore error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn, **kwargs) -> None:
    fn(**kwargs)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if not predicate(value):
        raise AssertionError(f"condition never satisfied, last value={value!r}")
    return value


def _create_ssm_managed_instance(ctx) -> str:
    """Launch a t3.micro EC2 instance with an SSM-managed-instance role and wait until its
    SSM Agent registers Online. Registers full teardown (instance, profile, role)."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_INSTANCE_ROLE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_INSTANCE_ROLE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-ssmprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-ssm-behav-")
    instance_id = None
    last_err: Exception | None = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and instance_id is None:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterCombination",
            ):
                raise
            time.sleep(5)
    if instance_id is None:
        raise AssertionError(f"could not launch SSM-managed instance: {last_err}")

    def _terminate_and_wait() -> None:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_terminate_and_wait)

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    def _ping_probe() -> dict[str, Any] | None:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        return infos[0] if infos else None

    _poll_until(
        _ping_probe,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=420.0,
        interval_s=10.0,
    )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

