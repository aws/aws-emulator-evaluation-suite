"""service-deployment-timestamp-precision-consistent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-deployment-timestamp-precision-consistent"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A service's createdAt and its initial service deployment's createdAt are stable across repeated reads,
    and the deployment's createdAt is never earlier than the service's.
    """
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-tsvc-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]

    family = ctx.unique_name("sim2real-ecs-tsvc-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "amazonlinux:2", "memory": 128, "essential": True}],
    )["taskDefinition"]["taskDefinitionArn"]

    service_name = ctx.unique_name("sim2real-ecs-tsvc-svc-")
    # desiredCount=0 with the EC2 launch type needs no capacity providers, VPC, or actual
    # container instances -- it only exercises the service/deployment bookkeeping.
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="EC2",
        tags=[{"key": "sim2real", "value": "true"}],
    )

    def _delete_service_and_cluster():
        # ctx.on_cleanup's own budget is 60s total (DEFAULT_CLEANUP_TIMEOUT_S) -- a 60s inner
        # deadline here left DeleteCluster no guaranteed time to run at all once the service
        # took a while to settle, and a cluster that never gets deleted is a silent leak the
        # engine has no way to surface. Split the budget so DeleteCluster always gets a turn,
        # and retry it: ECS can still answer ClusterContainsServicesException for a few seconds
        # after the service itself reports INACTIVE.
        ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
        wait_deadline = time.monotonic() + 35
        while time.monotonic() < wait_deadline:
            resp = ecs.describe_services(cluster=cluster_arn, services=[service_name])
            services = resp.get("services", [])
            if not services or services[0]["status"] == "INACTIVE":
                break
            time.sleep(2)
        delete_deadline = time.monotonic() + 20
        last_err: ClientError | None = None
        while time.monotonic() < delete_deadline:
            try:
                ecs.delete_cluster(cluster=cluster_arn)
                return
            except ClientError as err:
                last_err = err
                time.sleep(2)
        raise AssertionError(f"DeleteCluster for {cluster_arn} never succeeded in cleanup: {last_err}")

    ctx.on_cleanup(_delete_service_and_cluster)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    # The service deployment ARN isn't on the DescribeServices response -- ListServiceDeployments
    # is the documented way to resolve it (it's created implicitly by CreateService).
    deadline = time.monotonic() + 30
    deployment_arn = None
    while time.monotonic() < deadline:
        deployments = ecs.list_service_deployments(cluster=cluster_arn, service=service_name).get(
            "serviceDeployments", []
        )
        if deployments:
            deployment_arn = deployments[0]["serviceDeploymentArn"]
            break
        time.sleep(2)
    assert deployment_arn, "CreateService produced no discoverable service deployment"

    created_at_1 = _assert_stable_over_window(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]["createdAt"],
        window_s=4.0,
        poll_interval_s=2.0,
        label="service createdAt drifted across repeated DescribeServices calls",
    )

    dep_created_1 = _assert_stable_over_window(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0][
            "createdAt"
        ],
        window_s=4.0,
        poll_interval_s=2.0,
        label="service deployment createdAt drifted across repeated DescribeServiceDeployments calls",
    )

    # The deployment is minted implicitly, moments after the service row itself, as a
    # consequence of CreateService -- so its createdAt must never precede the service's
    # own createdAt. (On real AWS the two are never equal either -- the
    # deployment record consistently lands a couple of seconds after the service does.)
    assert dep_created_1 >= created_at_1, (
        f"service deployment createdAt {dep_created_1!r} precedes its own service's "
        f"createdAt {created_at_1!r} -- the deployment cannot exist before the service does"
    )


def _assert_stable_over_window(read_fn, *, window_s: float, poll_interval_s: float, label: str):
    """Read once, then keep re-reading on a bounded deadline for window_s -- every
    re-read must exactly match the first value. Failing fast on any mismatch (rather
    than a single before/after pair) catches a value that drifts partway through the
    window, not just at its two endpoints."""
    first = read_fn()
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        time.sleep(poll_interval_s)
        current = read_fn()
        assert current == first, f"{label}: {first!r} != {current!r}"
    return first


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
