"""execute-command-unknown-task."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-unknown-task"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_BOGUS_TASK = "00000000000000000000000000000000"

_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]
_ECS_TAGS = [{"key": "sim2real:managed", "value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExecuteCommand on a fabricated task id is refused InvalidParameterException with the exact
    task-not-found message, a real new task gets the exact not-enabled refusal, and DescribeTasks
    finds the real task but reports the fabricated id MISSING."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx, ecs)
    real_task_arn = _run_recognized_task(ctx, ecs, cluster_arn)

    # Positive control: DescribeTasks recognizes a real task this check created.
    real_described = ecs.describe_tasks(cluster=cluster_arn, tasks=[real_task_arn])
    assert not real_described.get("failures"), f"a real task was unexpectedly reported missing: {real_described}"
    assert len(real_described["tasks"]) == 1, f"expected exactly one real task, got {real_described['tasks']}"

    # ExecuteCommand rejects the real task too (its agent has never reached RUNNING),
    # but not necessarily with a DIFFERENT code than the fabricated id below -- real AWS
    # returns InvalidParameterException for both, so this is a sanity check, not the
    # discriminator.
    real_error = _expect_error(
        lambda: ecs.execute_command(
            cluster=cluster_arn, task=real_task_arn, container="app", command="/bin/sh", interactive=True
        )
    )
    assert real_error == _EXEC_NOT_AVAILABLE, f"expected {_EXEC_NOT_AVAILABLE!r}, got {real_error!r}"

    bogus_error = _expect_error(
        lambda: ecs.execute_command(cluster=cluster_arn, task=_BOGUS_TASK, command="/bin/sh", interactive=True)
    )
    expected = (
        "InvalidParameterException",
        "The specified task was not found. Specify a valid task ID and try again.",
    )
    assert bogus_error == expected, f"expected {expected!r}, got {bogus_error!r}"

    # The actual discriminator, via a DIFFERENT operation than the one under test:
    # DescribeTasks must report the fabricated id as MISSING, unlike the real task above.
    described = ecs.describe_tasks(cluster=cluster_arn, tasks=[_BOGUS_TASK])
    assert described["tasks"] == [], f"fabricated task id unexpectedly resolved to a task: {described['tasks']}"
    failures = described.get("failures", [])
    assert len(failures) == 1, f"expected exactly one DescribeTasks failure for the fabricated id, got {failures}"
    assert failures[0].get("reason") == "MISSING", f"expected reason MISSING, got {failures[0]}"


# ExecuteCommand's refusal while the task's exec agent is not running, or exec is not enabled.
_EXEC_NOT_AVAILABLE = (
    "InvalidParameterException",
    "The execute command failed because execute command was not enabled when the task was run "
    "or the execute command agent isn't running. Wait and try again or run a new task with "
    "execute command enabled and try again.",
)


# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _expect_error(fn, attempts: int = 7):
    """Return the (code, message) *fn* is rejected with, retrying through throttles."""
    for i in range(attempts):
        error = _error(fn)
        if error[0] not in _THROTTLE_CODES:
            return error
        time.sleep(min(2.0 * (2**i), 20.0))
    raise AssertionError(f"still throttled after {attempts} attempts")


def _retry_throttled(fn, attempts: int = 7, base_delay: float = 2.0):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(min(base_delay * (2**i), 20.0))
    raise last


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound", "NoSuchEntity")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _create_cluster(ctx, ecs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    resp = _retry_throttled(lambda: ecs.create_cluster(clusterName=name, tags=_ECS_TAGS, **kwargs))
    arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=arn)))
    return arn


def _provision_network(ctx):
    """A dedicated VPC + subnet for the one Fargate RunTask call this check makes.

    No internet gateway or route is needed: the check never waits for the task to reach RUNNING,
    only for ECS's control plane to acknowledge that the task exists.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]

    def _teardown_subnet():
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", [])
            if not enis:
                break
            time.sleep(5)
        _best_effort(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    ctx.on_cleanup(_teardown_subnet)

    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return subnet_id, sg_id


def _create_task_role(ctx) -> str:
    """RunTask rejects enableExecuteCommand=True outright (InvalidParameterException,
    synchronously, before any networking) unless the task has a task role -- so this
    check needs one even though it never waits long enough to need the SSM permissions
    that role would need to actually connect."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-ecs-taskrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _run_recognized_task(ctx, ecs, cluster_arn) -> str:
    """Get ECS's control plane to recognize a real task ARN, without waiting for it
    to reach RUNNING (which the account's Fargate networking cannot reliably reach
    within this check's budget, and which this check does not need: it only needs a
    task id ECS treats as EXISTING, to contrast against one it has never heard of)."""
    subnet_id, sg_id = _provision_network(ctx)
    task_role_arn = _create_task_role(ctx)

    family = ctx.unique_name("sim2real-behav-ecs-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ECS_TAGS,
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "60"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn])))
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.deregister_task_definition(taskDefinition=td_arn)))

    def _attempt_run():
        try:
            return ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                enableExecuteCommand=True,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
            )
        except ClientError as exc:
            # Freshly-created IAM roles are eventually consistent -- ECS can transiently
            # fail to assume the just-created task role for a short window after CreateRole.
            if exc.response.get("Error", {}).get("Code") == "ClientException" and "unable to assume the role" in str(exc):
                return None
            raise

    run_resp = _poll_until(_attempt_run, lambda r: r is not None, timeout_s=60, interval_s=5)
    if run_resp.get("failures"):
        raise AssertionError(f"RunTask reported failures: {run_resp['failures']}")
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop_and_wait():
        _best_effort(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behavioral-cleanup"))
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn]).get("tasks", [])
            if not tasks or tasks[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_stop_and_wait)

    # DescribeTasks is eventually consistent immediately after RunTask -- the fresh
    # ARN can be briefly invisible, so poll (bounded) rather than assume it is there.
    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn]).get("tasks", []),
        lambda tasks: bool(tasks),
        timeout_s=30,
    )
    return task_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
