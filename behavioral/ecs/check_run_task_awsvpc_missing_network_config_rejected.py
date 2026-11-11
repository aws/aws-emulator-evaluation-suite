"""run-task-awsvpc-missing-network-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-awsvpc-missing-network-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


def _ensure_ecs_slr(ctx):
    """RunTask does not implicitly create AWSServiceRoleForECS the way CreateService does,
    so in an account that has never run a Fargate task, RunTask fails with InvalidParameterException
    ("Unable to assume the service linked role") regardless of networkConfiguration -- which would
    make the positive control below fail for a reason unrelated to this check. The caller absorbs
    the propagation delay with a bounded retry (_call_with_slr_retry), not a sleep here."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        if code not in ("InvalidInput", "InvalidInputException") or message != (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a different suffix."
        ):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc


def _call_with_slr_retry(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with InvalidParameterException
    ('Unable to assume the service linked role...') while a freshly created
    AWSServiceRoleForECS propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "service linked role" not in msg.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group in shared network")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask of an awsvpc Fargate task definition without networkConfiguration fails with
    InvalidParameterException and its exact message and places no task, while the same definition run
    with networkConfiguration places exactly one task.
    """
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]

    def _cleanup_cluster():
        try:
            ecs.delete_cluster(cluster=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_cluster)

    family = ctx.unique_name("sim2real-ecs-fam-")
    registered = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]

    def _cleanup():
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup)

    def _tasks():
        return ecs.list_tasks(cluster=cluster_arn)["taskArns"]

    assert _tasks() == [], f"the cluster must start with no tasks, got {_tasks()}"

    # Positive control: the SAME task definition, WITH networkConfiguration, must run.
    _ensure_ecs_slr(ctx)
    subnet_id, sg_id = _default_network(ctx)
    control_resp = _call_with_slr_retry(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet_id],
                    "securityGroups": [sg_id],
                    "assignPublicIp": "ENABLED",
                }
            },
        )
    )
    assert not control_resp.get("failures"), (
        "positive control: the same task definition WITH networkConfiguration must run, "
        f"got failures: {control_resp.get('failures')}"
    )
    control_arns = [t["taskArn"] for t in control_resp.get("tasks", [])]
    assert control_arns, "positive control RunTask returned no tasks"
    control_arn = control_arns[0]
    ctx.on_cleanup(
        lambda: ecs.stop_task(cluster=cluster_arn, task=control_arn, reason="behavioral-cleanup")
    )
    assert set(_tasks()) == {control_arn}, (
        f"expected only the control task to exist after the positive control, got {_tasks()}"
    )

    # Negative: the same task definition, run WITHOUT networkConfiguration, must be rejected.
    code = None
    message = ""
    task_arns = []
    try:
        resp = ecs.run_task(
            cluster=cluster_arn, taskDefinition=arn, launchType="FARGATE", count=1
        )
        task_arns = [t["taskArn"] for t in resp.get("tasks", [])]
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code")
        message = err.response.get("Error", {}).get("Message", "")

    if task_arns:
        # If nothing raised, the task must not have actually been created (a fully
        # permissive emulator would let it through without the required network setup).
        for a in task_arns:
            ecs.stop_task(cluster=cluster_arn, task=a, reason="cleanup-should-not-have-existed")
        raise AssertionError(
            "RunTask should reject an awsvpc/Fargate task definition run without "
            "networkConfiguration, but it created a task instead"
        )

    # Real ECS rejects this with InvalidParameterException and a message that names the
    # missing network configuration.
    assert code == "InvalidParameterException", (
        f"expected an InvalidParameterException rejection, got {code} ({message})"
    )
    assert message == "Network Configuration must be provided when networkMode 'awsvpc' is specified.", f"refusal message {message!r}"

    # Effect absent, via an independent read: the rejected call must not have created
    # anything beyond the positive control's own task.
    assert set(_tasks()) == {control_arn}, (
        f"the rejected RunTask must not have created a task, got {_tasks()}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
