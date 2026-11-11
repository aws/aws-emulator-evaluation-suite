"""maintenance-window-cutoff-blocks-task-execution-near-end."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "maintenance-window-cutoff-blocks-task-execution-near-end"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ssm"]

_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


# timing:real-time — schedule: 180 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
      "timing:real-time")
def run(ctx) -> None:
    """A cron window with Duration 3 and Cutoff 2 fires and schedules its RUN_COMMAND task.

    Execution inside the cutoff period is not observed."""
    ssm = ctx.client("ssm")

    target_instance_id = _launch_ssm_managed_instance(ctx)


    # Fire a few minutes out so a real WindowExecution starts within the bounded poll.
    target = datetime.now(timezone.utc) + timedelta(minutes=3)
    cron = f"cron({target.minute} {target.hour} * * ? *)"

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule=cron,
        ScheduleTimezone="UTC",
        Duration=3,
        Cutoff=2,
        AllowUnassociatedTargets=True,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    window = ssm.get_maintenance_window(WindowId=window_id)
    assert window["Duration"] == 3, window
    assert window["Cutoff"] == 2, window

    task_id = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        Targets=[{"Key": "InstanceIds", "Values": [target_instance_id]}],
        MaxConcurrency="1",
        MaxErrors="1",
        TaskInvocationParameters={"RunCommand": {"Parameters": {"commands": ["echo hi"]}}},
    )["WindowTaskId"]
    ctx.on_cleanup(
        lambda: ssm.deregister_task_from_maintenance_window(
            WindowId=window_id, WindowTaskId=task_id
        )
    )

    # CutoffBehavior is optional on registration; AWS omits it from the response when never
    # supplied rather than materializing a CONTINUE_TASK default.
    task = ssm.get_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id)
    assert task["WindowId"] == window_id, task
    assert task["TaskArn"] == "AWS-RunShellScript", task
    assert task.get("CutoffBehavior") in (None, "CONTINUE_TASK", "CANCEL_TASK"), task

    execution_id = _poll_for_execution(ssm, window_id, timeout_s=360.0)
    assert execution_id is not None, (
        f"the cron Schedule {cron!r} (UTC) never produced a live WindowExecution for "
        f"{window_id} within the poll window"
    )

    # A few minutes into a 3-hour window with a 2-hour cutoff is outside the cutoff period, so
    # the task must be scheduled. Task identities carry TaskArn, not the registered WindowTaskId.
    task_identities = _poll_for_task_identities(ssm, execution_id, timeout_s=300.0)
    if not task_identities:
        # A finished execution reports a terminal Status with populated TaskIds.
        execution = _poll_for_terminal_execution(ssm, execution_id, timeout_s=300.0)
        assert execution["TaskIds"], (
            f"WindowExecution {execution_id} reached terminal Status="
            f"{execution.get('Status')!r} without ever scheduling the registered task "
            f"{task_id!r} against the real managed node {target_instance_id!r}: {execution}"
        )
    else:
        assert any(t["TaskArn"] == "AWS-RunShellScript" for t in task_identities), task_identities


def _poll_for_execution(ssm, window_id: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_maintenance_window_executions(WindowId=window_id)
        executions = resp.get("WindowExecutions", [])
        if executions:
            return executions[0]["WindowExecutionId"]
        time.sleep(10.0)
    return None


def _poll_for_task_identities(ssm, execution_id: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    identities: list = []
    while time.monotonic() < deadline:
        resp = ssm.describe_maintenance_window_execution_tasks(WindowExecutionId=execution_id)
        identities = resp.get("WindowExecutionTaskIdentities", [])
        if identities:
            return identities
        time.sleep(5.0)
    return identities


def _poll_for_terminal_execution(ssm, execution_id: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    execution = ssm.get_maintenance_window_execution(WindowExecutionId=execution_id)
    while time.monotonic() < deadline:
        execution = ssm.get_maintenance_window_execution(WindowExecutionId=execution_id)
        if execution.get("Status") not in ("PENDING", "IN_PROGRESS"):
            return execution
        time.sleep(10.0)
    return execution


def _wait_for_agent_online(
    ctx, instance_id: str, timeout_s: float = 600.0, interval_s: float = 15.0
) -> None:
    ssm = ctx.client("ssm")
    if ctx.time_left() is not None:
        timeout_s = max(1.0, min(timeout_s, ctx.time_left() - 60.0))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} never reached PingStatus=Online within {timeout_s:.0f}s"
        " (SSM Agent never registered)"
    )


def _launch_ssm_managed_instance(ctx, extra_tags=None) -> str:
    from botocore.exceptions import ClientError

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
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
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

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]

    tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-node-")}]
    if extra_tags:
        tags.extend(extra_tags)

    instance_id = None
    # EC2 rejects a new instance profile with InvalidParameterValue until IAM propagates.
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(5.0)
                continue
            raise
    if instance_id is None:
        raise AssertionError("could not launch an EC2 instance for the SSM managed node")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_for_agent_online(ctx, instance_id)
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
