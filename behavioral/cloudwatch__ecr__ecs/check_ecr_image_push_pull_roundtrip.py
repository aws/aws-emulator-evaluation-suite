"""ecr-image-push-pull-roundtrip."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecr-image-push-pull-roundtrip"

GROUP = "image-roundtrip"

SERVICES = ["cloudwatch", "ecr", "ecs"]

PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_CLUSTER_BUSY = ("ClusterContainsTasksException", "ClusterContainsServicesException",
                 "UpdateInProgressException")

ECS_TASK_EXECUTION_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)


# Each create_* registers its teardown via ctx.on_cleanup; LIFO order stops the task before
# the task def, cluster, role and repository are removed.
def _default_subnets(ctx) -> list[str]:
    """Public subnet IDs for the awsvpc networkConfiguration Fargate requires; raises if none exist."""
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
        ).get("Vpcs", [])
        if not vpcs:
            raise AssertionError("no shared network VPC available for Fargate tasks")
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    except AssertionError:
        raise
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AssertionError(f"unable to resolve network subnets: {exc}") from exc
    ids = [s["SubnetId"] for s in subnets]
    if not ids:
        raise AssertionError("shared network has no subnets for Fargate tasks")
    return ids


def _awsvpc_config(ctx) -> dict:
    return {
        "awsvpcConfiguration": {
            "subnets": _default_subnets(ctx),
            "assignPublicIp": "ENABLED",  # required so a public subnet task can pull the image
        }
    }


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create the ECS service-linked role idempotently: RunTask (unlike CreateService) does not
    auto-create it, and fails with "Unable to assume the service linked role" without it."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception as e:  # noqa: BLE001 - already-exists is success
        msg = str(e).lower()
        if (
            "has been taken" not in msg
            and "already" not in msg
            and "invalidinput" not in msg
        ):
            pass  # non-exists errors: let the subsequent RunTask surface the real problem


def _task_execution_role_arn(ctx) -> str:
    """Create a role trusted by ecs-tasks.amazonaws.com with AmazonECSTaskExecutionRolePolicy and a
    detach-then-delete teardown; IAM propagation lag is absorbed by `_run_fargate_task`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-ecs-tasks-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
        ],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        # A role must have its managed policy detached before it can be deleted.
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn=ECS_TASK_EXECUTION_POLICY
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ECS_TASK_EXECUTION_POLICY)
    return arn


def _create_repo(ctx, **kwargs) -> dict:
    name = ctx.unique_name("sim2real-xsvc-ecr-repo-")
    ecr = ctx.client("ecr")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _create_cluster(ctx) -> dict:
    name = ctx.unique_name("sim2real-xsvc-ecs-cluster-")
    ecs = ctx.client("ecs")
    resp = ecs.create_cluster(clusterName=name)

    def _cleanup() -> None:
        # A stopping task can still block cluster delete briefly: retry exactly that, then raise.
        deadline = time.monotonic() + 60
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                if code not in _CLUSTER_BUSY or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return resp["cluster"]


def _register_fargate_task_def(ctx, container_defs, execution_role_arn=None) -> dict:
    family = ctx.unique_name("sim2real-xsvc-ecs-taskdef-fg-")
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=family,
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))
    return td


def _run_fargate_task(
    ctx, cluster: str, task_def_arn: str, retry_budget_s: float = 60.0
) -> dict:
    """RunTask, retried within a bound while it fails with "unable to assume the role" because the
    new execution role has not yet propagated in IAM."""
    _ensure_ecs_service_linked_role(ctx)
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + retry_budget_s
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                networkConfiguration=_awsvpc_config(ctx),
            )
        except Exception as exc:  # noqa: BLE001 - narrowed by message check below
            msg = str(exc)
            if "assume the role" not in msg.lower() and "AccessDenied" not in msg:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"RunTask never succeeded within {retry_budget_s}s "
                    f"(IAM propagation?): {exc}"
                ) from exc
            time.sleep(5)
            continue
        failures = resp.get("failures", [])
        role_failure = next(
            (f for f in failures if "assume" in f.get("reason", "").lower()), None
        )
        if role_failure:
            if time.monotonic() >= deadline:
                raise AssertionError(f"RunTask failures: {failures}")
            time.sleep(5)
            continue
        for t in resp.get("tasks", []):
            ctx.on_cleanup(
                lambda a=t["taskArn"]: ecs.stop_task(cluster=cluster, task=a)
            )
        return resp


def _await_task_running(
    ctx, cluster: str, task_arn: str, timeout_s: float = 420
) -> dict:
    """Poll DescribeTasks until the task is RUNNING; a STOPPED task fails with its stoppedReason."""
    ecs = ctx.client("ecs")

    def probe() -> dict:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return tasks[0] if tasks else {}

    task = _poll_until(
        probe,
        lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"),
        timeout_s=timeout_s,
        interval_s=5,
        description=f"task {task_arn} RUNNING",
    )
    assert task.get("lastStatus") == "RUNNING", (
        f"task did not reach RUNNING: lastStatus={task.get('lastStatus')} "
        f"stoppedReason={task.get('stoppedReason')}"
    )
    return task


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """An image pushed with docker to a private ECR repository is listed by ListImages, and an ECS
    Fargate task using that image pulls it and reaches RUNNING."""
    from fidelity_tests_runner import require_tools

    require_tools("docker", "aws")

    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    repo_uri = repo["repositoryUri"]
    registry = repo_uri.split("/")[0]
    image_ref = f"{repo_uri}:v1"

    _run_script(
        ctx,
        f"""
        aws ecr get-login-password --region {ctx.region} \\
            | docker login --username AWS --password-stdin {registry}
        docker pull {PUBLIC_IMAGE}
        docker tag {PUBLIC_IMAGE} {image_ref}
        docker push {image_ref}
        """,
        timeout_s=420,
    )

    images = ecr.list_images(repositoryName=repo["repositoryName"]).get("imageIds", [])
    assert any(i.get("imageTag") == "v1" for i in images), (
        f"pushed tag missing: {images}"
    )

    # The execution role supplies ECR auth for the private image pull.
    exec_role = _task_execution_role_arn(ctx)
    cluster = _create_cluster(ctx)
    container_defs = [
        {
            "name": "app",
            "image": image_ref,
            "essential": True,
            "command": ["sh", "-c", "echo pulled-from-ecr; sleep 3600"],
        }
    ]
    td = _register_fargate_task_def(ctx, container_defs, execution_role_arn=exec_role)

    resp = _run_fargate_task(ctx, cluster["clusterName"], td["taskDefinitionArn"])
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')}"
    task_arn = resp["tasks"][0]["taskArn"]
    _await_task_running(ctx, cluster["clusterName"], task_arn, timeout_s=300)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str -> shell=True, or argv list) with the check's AWS creds and region
    from ctx.subprocess_env. Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with the check's AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


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
