"""update-service-deployment-controller-change-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-deployment-controller-change-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService cannot reassign the deploymentController of an EXTERNAL service with no
    primary task set (InvalidParameterException naming it), the controller stays EXTERNAL, and
    healthCheckGracePeriodSeconds on the same service still updates."""
    ecs = ctx.client("ecs")
    tag_spec = [{"key": "sim2real", "value": "true"}]

    cluster_name = ctx.unique_name("sim2real-depctrl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=tag_spec)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    service_name = ctx.unique_name("sim2real-depctrl-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        desiredCount=0,
        schedulingStrategy="REPLICA",
        deploymentController={"type": "EXTERNAL"},
        tags=tag_spec,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    described = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
    assert described["deploymentController"]["type"] == "EXTERNAL", (
        f"expected EXTERNAL deploymentController right after creation, got {described['deploymentController']!r}"
    )

    # Negative: with no primary task set, the deploymentController of an
    # EXTERNAL-controller service cannot be reassigned via UpdateService.
    code, message = _error(
        lambda: ecs.update_service(
            cluster=cluster_arn,
            service=service_name,
            deploymentController={"type": "ECS"},
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException, got {code!r}"
    )
    expected_message = (
        "Updating the deployment controller requires a primary taskset in the service. "
        "Please ensure your service has a primary taskset and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the controller type is unchanged.
    described = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
    assert described["deploymentController"]["type"] == "EXTERNAL", (
        f"deploymentController changed despite the rejected update: {described['deploymentController']}"
    )

    # Positive control: an allowed field updates, confirmed by an independent read.
    ecs.update_service(
        cluster=cluster_arn,
        service=service_name,
        healthCheckGracePeriodSeconds=17,
    )
    described = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
    assert described["healthCheckGracePeriodSeconds"] == 17, (
        f"expected healthCheckGracePeriodSeconds=17 on independent describe_services read, "
        f"got {described.get('healthCheckGracePeriodSeconds')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the deploymentController update to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
