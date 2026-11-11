"""continue-service-deployment-advances-rollout."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "continue-service-deployment-advances-rollout"
GROUP = "state-machine"
SERVICES = ["ecs"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ContinueServiceDeployment on a well-formed but nonexistent deployment id under a real
    cluster and service is rejected with InvalidParameterException rather than doing nothing."""

    ecs = ctx.client("ecs")
    tag_spec = [{"key": "sim2real-check", "value": CHECK}]

    # A bogus serviceDeploymentArn only reaches ServiceDeploymentNotFoundException once its
    # cluster/service path segments resolve to REAL resources -- ECS validates the referenced
    # cluster (and service) before it ever inspects the trailing deployment id, so pointing the
    # ARN at wholly nonexistent cluster/service names surfaces ClusterNotFoundException instead
    # of the deployment-specific error this check is meant to verify. Stand up a real cluster +
    # service and only fabricate the trailing deployment id.
    cluster_name = ctx.unique_name("sim2real-ecs-csdcl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=tag_spec)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    family = ctx.unique_name("sim2real-ecs-csdtd-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "cpu": 128, "memory": 128, "essential": True}
        ],
        tags=tag_spec,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def_arn))

    service_name = ctx.unique_name("sim2real-ecs-csdsvc-")
    ecs.create_service(
        cluster=cluster_arn, serviceName=service_name, taskDefinition=task_def_arn,
        desiredCount=0, launchType="EC2", tags=tag_spec,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # The trailing deployment-id segment of a real serviceDeploymentArn is a 32-char lowercase
    # hex token (e.g. "b6b8bd11cc1b4b95bd0f8b04f4d5722c"), not an arbitrary numeric string. Even
    # with a well-formed-but-nonexistent hex id (and a real cluster/service in the path), ECS does
    # NOT surface ServiceDeploymentNotFoundException here: real testing shows it rejects the
    # request with InvalidParameterException instead -- ContinueServiceDeployment validates that
    # the referenced deployment is actually resolvable/addressable (which requires it to belong to
    # a service using the blue/green deployment strategy in the first place) before it would ever
    # reach a not-found check, so a bogus id under a plain rolling-deployment service surfaces the
    # parameter-validation error rather than a not-found error.
    import uuid

    bogus_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:service-deployment/"
        f"{cluster_name}/{service_name}/{uuid.uuid4().hex}"
    )
    code, message = _error(
        lambda: ecs.continue_service_deployment(serviceDeploymentArn=bogus_arn, hookId="sim2real-hook")
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a nonexistent deployment id under a "
        f"real cluster/service, got {code}"
    )
    expected_message = "The ServiceDeployment ARN is invalid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
