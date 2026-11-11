"""op-contract-describeServices."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeServices"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeServices returns real service state and raises ClusterNotFoundException for a bogus cluster."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-behav-td-")
    reg = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=0,
        launchType="EC2",
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    resp = ecs.describe_services(cluster=cluster_name, services=[service_name])
    assert resp["failures"] == [], f"expected no failures, got {resp['failures']}"
    svc = resp["services"][0]
    assert svc["serviceName"] == service_name, f"expected {service_name}, got {svc['serviceName']}"
    assert svc["status"] == "ACTIVE", f"expected ACTIVE, got {svc['status']}"
    assert svc["desiredCount"] == 0, f"expected desiredCount 0, got {svc['desiredCount']}"
    assert svc["taskDefinition"] == td_arn, f"expected {td_arn}, got {svc['taskDefinition']}"

    missing = ecs.describe_services(cluster=cluster_name, services=["sim2real-no-such-service-xyz"])
    assert missing["services"] == [], f"expected no services, got {missing['services']}"
    assert len(missing["failures"]) == 1, f"expected 1 failure, got {missing['failures']}"
    assert missing["failures"][0]["reason"] == "MISSING", f"expected MISSING, got {missing['failures'][0]['reason']}"

    err, message = _error(
        lambda: ecs.describe_services(
            cluster="sim2real-no-such-cluster-xyz", services=[service_name]
        )
    )
    assert err == "ClusterNotFoundException", f"expected ClusterNotFoundException, got {err}"
    expected_message = 'Cluster not found.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
