"""maintenance-window-execution-task-invocation-times-out."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-execution-task-invocation-times-out"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ssm"]

_INSTANCE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# TimeoutSeconds on a RUN_COMMAND task bounds only whether the command starts in time; a 60s
# command with TimeoutSeconds=30 runs to completion and reports SUCCESS.
_TASK_TIMEOUT_SECONDS = 30
_COMMAND_SLEEP_SECONDS = 60


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A RUN_COMMAND invocation running past its TimeoutSeconds is not killed mid-run.

    The invocation reports SUCCESS with a duration exceeding TimeoutSeconds."""
    ssm = ctx.client("ssm")
    instance_id = _create_ssm_managed_instance(ctx)

    window = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-ssm-mw-"),
        Schedule="cron(0/1 * * * ? *)",
        ScheduleTimezone="UTC",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=False,
    )
    window_id = window["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    target = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": [instance_id]}],
    )
    window_target_id = target["WindowTargetId"]
    ctx.on_cleanup(
        lambda: ssm.deregister_target_from_maintenance_window(
            WindowId=window_id, WindowTargetId=window_target_id
        )
    )

    task = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        Targets=[{"Key": "WindowTargetIds", "Values": [window_target_id]}],
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        TaskInvocationParameters={
            "RunCommand": {
                "Parameters": {"commands": [f"sleep {_COMMAND_SLEEP_SECONDS}"]},
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
            }
        },
        Priority=1,
        MaxConcurrency="1",
        MaxErrors="1",
    )
    window_task_id = task["WindowTaskId"]
    ctx.on_cleanup(
        lambda: ssm.deregister_task_from_maintenance_window(
            WindowId=window_id, WindowTaskId=window_task_id
        )
    )

    def _execution_probe() -> list[dict[str, Any]]:
        resp = ssm.describe_maintenance_window_executions(WindowId=window_id)
        return resp.get("WindowExecutions", [])

    executions = _poll_until(_execution_probe, lambda e: len(e) > 0, timeout_s=200.0, interval_s=10.0)
    window_execution_id = executions[0]["WindowExecutionId"]

    def _task_probe() -> list[dict[str, Any]]:
        resp = ssm.describe_maintenance_window_execution_tasks(WindowExecutionId=window_execution_id)
        return [t for t in resp.get("WindowExecutionTaskIdentities", []) if t.get("TaskArn") == "AWS-RunShellScript"]

    tasks = _poll_until(_task_probe, lambda t: len(t) == 1, timeout_s=90.0, interval_s=5.0)
    task_execution_id = tasks[0]["TaskExecutionId"]

    def _invocation_probe() -> list[dict[str, Any]]:
        resp = ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=window_execution_id, TaskId=task_execution_id
        )
        return resp.get("WindowExecutionTaskInvocationIdentities", [])

    invocations = _poll_until(
        _invocation_probe,
        lambda invs: len(invs) >= 1 and all(i.get("Status") in _TERMINAL for i in invs),
        timeout_s=150.0,
        interval_s=10.0,
    )
    assert len(invocations) == 1, f"expected exactly 1 invocation, got {len(invocations)}: {invocations!r}"
    invocation = invocations[0]
    assert invocation["Status"] == "SUCCESS", (
        f"expected invocation status SUCCESS (TimeoutSeconds does not kill a started command), "
        f"got {invocation.get('Status')!r} (StatusDetails={invocation.get('StatusDetails')!r})"
    )
    duration_s = (invocation["EndTime"] - invocation["StartTime"]).total_seconds()
    assert duration_s > _TASK_TIMEOUT_SECONDS, (
        f"expected the invocation to have run past its {_TASK_TIMEOUT_SECONDS}s TimeoutSeconds "
        f"before completing (proving it was not cut off at the timeout), measured "
        f"duration={duration_s:.1f}s"
    )


_TERMINAL = {"SUCCESS", "FAILED", "TIMED_OUT", "CANCELLED", "SKIPPED_OVERLAPPING"}


# ===== helpers =====


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 120.0,
    interval_s: float = 5.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_ssm_managed_instance(ctx) -> str:
    """Launch a t3.micro SSM-managed EC2 instance and wait until its SSM Agent is Online."""
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
