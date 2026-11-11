"""create-service-mismatched-launch-type-capacity-provider-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-service-mismatched-launch-type-capacity-provider-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService rejects a request that specifies both launchType and capacityProviderStrategy."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-ecs-mismatch-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    family = ctx.unique_name("sim2real-ecs-mismatch-td-")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def["taskDefinitionArn"]))

    bad_service_name = ctx.unique_name("sim2real-ecs-mismatch-svc-")
    code, message = _error(
        lambda: ecs.create_service(
            cluster=cluster_arn,
            serviceName=bad_service_name,
            taskDefinition=task_def["taskDefinitionArn"],
            desiredCount=0,
            launchType="EC2",
            capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        )
    )
    if code != "InvalidParameterException":
        raise AssertionError(repr(code))
    expected_message = (
        "Specifying both a launch type and capacity provider strategy is not supported. "
        "Remove one and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no service object was created.
    described = ecs.describe_services(cluster=cluster_arn, services=[bad_service_name])
    assert described["services"] == [], "a service was created despite the conflicting launchType/strategy request"
    failures = described.get("failures", [])
    assert any(f.get("reason") == "MISSING" for f in failures), (
        f"expected a MISSING failure for the rejected service name, got {failures!r}"
    )

    # Positive control: launchType alone (no strategy) is accepted.
    good_service_name = ctx.unique_name("sim2real-ecs-mismatch-ok-")
    good = ecs.create_service(
        cluster=cluster_arn,
        serviceName=good_service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=0,
        launchType="EC2",
        tags=[{"key": "sim2real", "value": "true"}],
    )["service"]
    good_arn = good["serviceArn"]
    ctx.on_cleanup(lambda: _delete_service_and_wait(ecs, cluster_arn, good_arn))

    # Terminal read is independent of the mutating CreateService response: a fresh
    # DescribeServices confirms the accepted request actually took effect at the target.
    redescribed = ecs.describe_services(cluster=cluster_arn, services=[good_arn])["services"]
    assert len(redescribed) == 1, f"expected the accepted service to be describable, got {redescribed!r}"
    assert redescribed[0]["status"] == "ACTIVE", (
        f"expected status ACTIVE for the accepted launchType-only service, got {redescribed[0]['status']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_service_and_wait(ecs, cluster_arn, service_arn, timeout_s=90.0):
    try:
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_services(cluster=cluster_arn, services=[service_arn])
        services = resp.get("services", [])
        if not services or services[0]["status"] == "INACTIVE":
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
