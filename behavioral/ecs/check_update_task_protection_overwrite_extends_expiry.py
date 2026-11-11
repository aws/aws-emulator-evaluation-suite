"""update-task-protection-overwrite-extends-expiry."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-overwrite-extends-expiry"
GROUP = "data-plane"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Calling UpdateTaskProtection twice with different expiresInMinutes REPLACES (does not
    add to) the prior expiry: the returned/persisted expirationDate always reflects only the
    latest call, per the documented "expiresInMinutes is always reset" behavior.
    """
    ecs = ctx.client("ecs")
    net = _default_network_config(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-utpe-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    family = ctx.unique_name("sim2real-ecs-utpe-td-")
    task_def_arn = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-ecs-utpe-svc-")
    _ensure_ecs_service_linked_role(ctx)
    _call_with_slr_retry(
        ctx,
        lambda: ecs.create_service(
            cluster=cluster_arn,
            serviceName=service_name,
            taskDefinition=task_def_arn,
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["securityGroups"],
                    "assignPublicIp": "ENABLED",
                }
            },
            tags=[{"key": "sim2real-check", "value": CHECK}],
        ),
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))
    )

    def _describe_service() -> dict:
        return ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]

    _poll_until(
        _describe_service,
        lambda s: s["runningCount"] == 1 and s["pendingCount"] == 0,
        timeout_s=480.0,
        interval_s=10.0,
    )

    task_arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name)["taskArns"]
    assert len(task_arns) == 1
    task_arn = task_arns[0]

    # First call: protect for 5 minutes.
    t0 = time.time()
    resp1 = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=5
    )
    assert resp1["failures"] == []
    exp1 = resp1["protectedTasks"][0]["expirationDate"].timestamp()
    assert abs(exp1 - (t0 + 5 * 60)) < 90, "first call's expiry should be ~5 minutes out"

    # Second call: replace with a 30-minute window.
    t1 = time.time()
    resp2 = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=30
    )
    assert resp2["failures"] == []
    exp2 = resp2["protectedTasks"][0]["expirationDate"].timestamp()

    replace_hypothesis = t1 + 30 * 60
    additive_hypothesis = t0 + 5 * 60 + 30 * 60
    assert abs(exp2 - replace_hypothesis) < 90, (
        f"expirationDate {exp2} should reflect ONLY the latest 30-minute call "
        f"(expected ~{replace_hypothesis}), not be additive with the first call"
    )
    assert abs(exp2 - additive_hypothesis) > 120, (
        "expirationDate must not be the sum of the two expiresInMinutes windows"
    )

    # GetTaskProtection must report the same, replaced expiry -- not a stale/added one.
    get_resp = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    assert get_resp["failures"] == []
    persisted = get_resp["protectedTasks"][0]
    assert persisted["protectionEnabled"] is True
    persisted_exp = persisted["expirationDate"].timestamp()
    assert abs(persisted_exp - exp2) < 5, "GetTaskProtection must reflect the latest UpdateTaskProtection call"


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_network_config(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch Fargate tasks")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch Fargate tasks into")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "securityGroups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _register_sleep_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    container = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command or ["sleep", "1800"],
        "essential": True,
    }
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[container],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    return resp["taskDefinition"]["taskDefinitionArn"]


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Proactively create AWSServiceRoleForECS so CreateService doesn't race the
    just-in-time SLR creation on a fresh account. Propagation delay, if any, is
    absorbed by _call_with_slr_retry's bounded retry around the actual CreateService
    call rather than by waiting here."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:
        pass


def _call_with_slr_retry(ctx, fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with InvalidParameterException
    ('Unable to assume the service linked role...') while AWSServiceRoleForECS propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", "")
            if "service linked role" not in msg.lower() or time.monotonic() >= deadline:
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
