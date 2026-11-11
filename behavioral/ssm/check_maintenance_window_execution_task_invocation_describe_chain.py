"""maintenance-window-execution-task-invocation-describe-chain."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-execution-task-invocation-describe-chain"
GROUP = "state-machine"
SERVICES = ["ssm"]


# timing:real-time — schedule: 180 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A fired RUN_COMMAND window task yields an execution, task and invocation chain.

    Each record is retrievable via Get* and listed by its Describe* counterpart with consistent
    ids, and the per-execution task id differs from the registered WindowTaskId."""
    ssm = ctx.client("ssm")
    instance_id = _launch_managed_instance(ctx)

    window_name = ctx.unique_name("sim2real-mw-chain-")
    window_id = ssm.create_maintenance_window(
        Name=window_name,
        Schedule=_one_shot_cron(minutes_ahead=3),
        Duration=2,
        Cutoff=0,
        AllowUnassociatedTargets=False,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": [instance_id]}],
    )["WindowTargetId"]

    window_task_id = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        Targets=[{"Key": "WindowTargetIds", "Values": [target_id]}],
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        MaxConcurrency="1",
        MaxErrors="1",
        TaskInvocationParameters={
            "RunCommand": {"Parameters": {"commands": ["echo sim2real-mw-chain-check"]}}
        },
    )["WindowTaskId"]

    executions = _poll_until(
        lambda: ssm.describe_maintenance_window_executions(WindowId=window_id)["WindowExecutions"],
        lambda execs: len(execs) > 0,
        timeout_s=480.0,
        interval_s=15.0,
    )
    assert executions, "maintenance window never produced an execution"
    execution_id = executions[0]["WindowExecutionId"]

    # AWS mints a fresh per-execution task id independent of the registered WindowTaskId; the
    # execution's TaskIds is the only source for the id the Get/Describe task calls need.
    execution = _poll_until(
        lambda: ssm.get_maintenance_window_execution(WindowExecutionId=execution_id),
        lambda r: bool(r.get("TaskIds")),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert execution["WindowExecutionId"] == execution_id, (
        f"GetMaintenanceWindowExecution returned WindowExecutionId="
        f"{execution['WindowExecutionId']!r}, expected {execution_id!r}"
    )
    reported_task_ids = execution.get("TaskIds", [])
    assert len(reported_task_ids) == 1, (
        f"expected the execution to report exactly one per-execution task id for the one "
        f"registered task, got {reported_task_ids!r}"
    )
    task_execution_id = reported_task_ids[0]
    assert task_execution_id != window_task_id, (
        f"expected the per-execution task id to differ from the registration-time "
        f"WindowTaskId {window_task_id!r} (real AWS mints a fresh id per execution); "
        f"got the same value {task_execution_id!r} back -- if AWS has started reusing "
        f"WindowTaskId as the execution id, the DescribeMaintenanceWindowExecutionTasks "
        f"lookup above should be re-keyed on it directly"
    )

    tasks = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_tasks(
            WindowExecutionId=execution_id
        )["WindowExecutionTaskIdentities"],
        lambda tasks: any(t["TaskExecutionId"] == task_execution_id for t in tasks),
        timeout_s=120.0,
        interval_s=10.0,
    )
    assert any(t["TaskExecutionId"] == task_execution_id for t in tasks), (
        f"DescribeMaintenanceWindowExecutionTasks never listed the execution's own reported "
        f"task id {task_execution_id!r}; saw TaskExecutionIds="
        f"{[t.get('TaskExecutionId') for t in tasks]!r}"
    )

    task_detail = ssm.get_maintenance_window_execution_task(
        WindowExecutionId=execution_id, TaskId=task_execution_id
    )
    assert task_detail["TaskExecutionId"] == task_execution_id, (
        f"GetMaintenanceWindowExecutionTask returned TaskExecutionId="
        f"{task_detail['TaskExecutionId']!r}, expected {task_execution_id!r}"
    )
    assert task_detail["TaskArn"] == "AWS-RunShellScript", (
        f"GetMaintenanceWindowExecutionTask returned TaskArn={task_detail['TaskArn']!r}, "
        f"expected 'AWS-RunShellScript'"
    )

    invocations = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=execution_id, TaskId=task_execution_id
        )["WindowExecutionTaskInvocationIdentities"],
        lambda invs: len(invs) > 0,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert invocations, "task never produced an invocation record"
    invocation_id = invocations[0]["InvocationId"]

    invocation_detail = ssm.get_maintenance_window_execution_task_invocation(
        WindowExecutionId=execution_id, TaskId=task_execution_id, InvocationId=invocation_id
    )
    assert invocation_detail["WindowExecutionId"] == execution_id, (
        f"GetMaintenanceWindowExecutionTaskInvocation returned WindowExecutionId="
        f"{invocation_detail['WindowExecutionId']!r}, expected {execution_id!r}"
    )
    assert invocation_detail["InvocationId"] == invocation_id, (
        f"GetMaintenanceWindowExecutionTaskInvocation returned InvocationId="
        f"{invocation_detail['InvocationId']!r}, expected {invocation_id!r}"
    )
    assert invocation_detail["Status"] is not None, (
        "GetMaintenanceWindowExecutionTaskInvocation returned no Status for "
        f"invocation {invocation_id!r}"
    )


def _one_shot_cron(minutes_ahead: int) -> str:
    target = datetime.now(timezone.utc) + timedelta(minutes=minutes_ahead)
    return f"cron({target.minute} {target.hour} {target.day} {target.month} ? {target.year})"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _default_subnet_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _launch_managed_instance(ctx) -> str:
    """Launch a t3.micro SSM-managed EC2 instance and wait for PingStatus=Online; return its id."""

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if not subnet_id:
        raise AssertionError(
            "no default VPC/subnet available to launch a test managed-instance EC2 host"
        )

    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    role_name = ctx.unique_name("sim2real-ssm-mi-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    profile_name = ctx.unique_name("sim2real-ssm-mi-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except ClientError:
            time.sleep(2)

    ami_id = _latest_al2023_ami(ctx)
    tag_name = ctx.unique_name("sim2real-ssm-mi-")

    instance_id = None
    launch_deadline = time.monotonic() + 60
    last_error: Exception | None = None
    while time.monotonic() < launch_deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": tag_name}]}
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            time.sleep(3)
    if instance_id is None:
        raise AssertionError(f"could not launch test instance: {last_error}")

    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    online_deadline = time.monotonic() + 480
    online = False
    while time.monotonic() < online_deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            online = True
            break
        time.sleep(15)
    if not online:
        raise AssertionError(
            f"EC2 instance {instance_id} did not register as an SSM managed node within "
            "8 minutes (agent bootstrap or outbound network egress issue in this environment)"
        )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
