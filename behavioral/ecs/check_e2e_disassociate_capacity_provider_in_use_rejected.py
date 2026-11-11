"""e2e-disassociate-capacity-provider-in-use-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-disassociate-capacity-provider-in-use-rejected"
GROUP = "e2e"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """RunTask naming an unassociated capacity provider is rejected (InvalidParameterException)
    and succeeds once it is associated; dropping that provider while its task is RUNNING is
    allowed and leaves the task running."""
    ecs = ctx.client("ecs")
    net = _default_network_config(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-neginuse-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    family = ctx.unique_name("sim2real-ecs-neginuse-td-")
    task_def_arn = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    # Associate only FARGATE to start -- FARGATE_SPOT is deliberately left unassociated.
    _ensure_ecs_service_linked_role(ctx)
    _call_with_slr_retry(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_arn,
            capacityProviders=["FARGATE"],
            defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        )
    )

    # RunTask against an unassociated provider must be rejected, not run on another provider.
    def _run_with_spot():
        return ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=task_def_arn,
            count=1,
            capacityProviderStrategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}],
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["securityGroups"],
                    "assignPublicIp": "ENABLED",
                }
            },
        )

    code, message = _error(_run_with_spot)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "The specified capacity provider strategy cannot contain a capacity provider that is not associated with the cluster. Associate the capacity provider with the cluster or specify a valid capacity provider and try again.", f"unexpected message: {message!r}"

    # Effect absent: no task was created against the unassociated provider.
    task_arns_after_reject = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert task_arns_after_reject == [], f"expected no tasks after rejected RunTask, got {task_arns_after_reject!r}"

    # --- positive control: associate FARGATE_SPOT too, then the identical call succeeds ---
    _call_with_slr_retry(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_arn,
            capacityProviders=["FARGATE", "FARGATE_SPOT"],
            defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        )
    )
    run_resp = _run_with_spot()
    assert run_resp["tasks"], f"RunTask failed to launch: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn)))

    def _describe_task() -> dict:
        return ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]

    running = _poll_until(
        _describe_task,
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=240.0,
        interval_s=10.0,
    )
    assert running["lastStatus"] == "RUNNING", f"task never reached RUNNING: {running.get('stoppedReason')}"

    # Disassociation only affects future placement, so dropping FARGATE_SPOT is allowed while
    # this FARGATE_SPOT task is RUNNING.
    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    )
    cluster_state = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0],
        lambda c: c["capacityProviders"] == ["FARGATE"],
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert cluster_state["capacityProviders"] == ["FARGATE"], (
        f"expected only FARGATE associated after disassociating FARGATE_SPOT, "
        f"got {cluster_state['capacityProviders']!r}"
    )
    still_running = _describe_task()
    assert still_running["lastStatus"] == "RUNNING", "existing task must be unaffected by disassociation"

    ecs.stop_task(cluster=cluster_arn, task=task_arn)
    _poll_until(_describe_task, lambda t: t["lastStatus"] == "STOPPED", timeout_s=180.0, interval_s=5.0)


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

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
    )
    return resp["taskDefinition"]["taskDefinitionArn"]


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create AWSServiceRoleForECS up front: a fresh account otherwise sees 'Unable to assume
    the service linked role' on its first ECS call. _call_with_slr_retry absorbs propagation."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:
        pass


def _call_with_slr_retry(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call through transient errors: InvalidParameterException while the ECS
    service-linked role propagates, or UpdateInProgressException while a cluster update settles."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", "")
            retriable = "service linked role" in msg.lower() or code == "UpdateInProgressException"
            if not retriable or time.monotonic() >= deadline:
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

