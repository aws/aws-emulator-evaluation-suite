"""update-task-protection-idempotent-reapply-same-window."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-idempotent-reapply-same-window"
GROUP = "data-plane"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Reapplying UpdateTaskProtection with the same expiresInMinutes (15) succeeds both times, each
    expirationDate is about 15 minutes after its own call and the second is 0-60 s after the first, and
    GetTaskProtection reports the second one.
    """
    ecs = ctx.client("ecs")
    net = _default_network_config(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-utpi-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    family = ctx.unique_name("sim2real-ecs-utpi-td-")
    task_def_arn = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-ecs-utpi-svc-")
    _ensure_ecs_service_linked_role(ctx)
    _call_with_slr_retry(
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
            tags=[{"key": "sim2real", "value": "true"}],
        )
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
    assert len(task_arns) == 1, f"expected exactly 1 task in the service, got {len(task_arns)}: {task_arns}"
    task_arn = task_arns[0]

    t0 = time.time()
    resp1 = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=15
    )
    assert resp1["failures"] == [], f"expected no failures on the first UpdateTaskProtection, got {resp1['failures']}"
    entry1 = resp1["protectedTasks"][0]
    assert entry1["protectionEnabled"] is True, f"expected protectionEnabled=True, got {entry1['protectionEnabled']}"
    exp1 = entry1["expirationDate"].timestamp()
    assert abs(exp1 - (t0 + 15 * 60)) < 90, (
        f"expected expirationDate ~{t0 + 15 * 60:.0f} (t0+15m), got {exp1:.0f}"
    )

    # Hold for a short window with no intervening UpdateTaskProtection call, polling
    # GetTaskProtection (an independent, bounded read) throughout: expiry must not drift
    # on its own while nothing has re-armed it.
    hold_deadline = time.monotonic() + 4.0
    while time.monotonic() < hold_deadline:
        held = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
        assert held["failures"] == [], f"expected no failures during hold, got {held['failures']}"
        held_entry = held["protectedTasks"][0]
        assert held_entry["protectionEnabled"] is True, (
            f"expected protection to remain enabled during the hold, got {held_entry['protectionEnabled']}"
        )
        held_delta = abs(held_entry["expirationDate"].timestamp() - exp1)
        assert held_delta < 5, (
            f"expirationDate drifted with no intervening UpdateTaskProtection call: "
            f"exp1={exp1}, held={held_entry['expirationDate'].timestamp()} (delta={held_delta:.1f}s)"
        )
        time.sleep(1)

    # Re-apply the exact same window while protection is already active -- must succeed
    # cleanly, not error as a duplicate/conflicting request.
    t1 = time.time()
    resp2 = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=15
    )
    assert resp2["failures"] == [], f"expected no failures on the second UpdateTaskProtection, got {resp2['failures']}"
    entry2 = resp2["protectedTasks"][0]
    assert entry2["protectionEnabled"] is True, f"expected protectionEnabled=True, got {entry2['protectionEnabled']}"
    exp2 = entry2["expirationDate"].timestamp()
    assert abs(exp2 - (t1 + 15 * 60)) < 90, (
        f"expected expirationDate ~{t1 + 15 * 60:.0f} (t1+15m), got {exp2:.0f}"
    )

    # The expiry must be a freshly-computed, stable window from the second call's own
    # timestamp -- close to the first call's expiry (since t1 is only ~4s after t0), not
    # drifted by some multiple of the 15-minute window (e.g. not ~30 minutes later).
    assert 0 <= (exp2 - exp1) < 60, (
        f"reapplying the same {15}-minute window should yield a stable expiry "
        f"(exp1={exp1}, exp2={exp2}, delta={exp2 - exp1})"
    )

    # GetTaskProtection reflects the latest (second) call's expiry.
    get_resp = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    assert get_resp["failures"] == [], f"expected no failures on GetTaskProtection, got {get_resp['failures']}"
    persisted = get_resp["protectedTasks"][0]
    assert persisted["protectionEnabled"] is True, (
        f"expected protectionEnabled=True after GetTaskProtection, got {persisted['protectionEnabled']}"
    )
    persisted_exp = persisted["expirationDate"].timestamp()
    assert abs(persisted_exp - exp2) < 5, (
        f"expected GetTaskProtection to reflect the second call's expiry ~{exp2:.0f}, got {persisted_exp:.0f}"
    )


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
        tags=[{"key": "sim2real", "value": "true"}],
    )
    return resp["taskDefinition"]["taskDefinitionArn"]


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Proactively create AWSServiceRoleForECS so CreateService doesn't race the
    just-in-time SLR creation on a fresh account. Any propagation delay is absorbed by
    `_call_with_slr_retry`'s bounded retry, not by waiting here."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:
        pass


def _call_with_slr_retry(fn, *, timeout_s=90.0, interval_s=5.0):
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
