"""create-service-invalid-name-characters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-invalid-name-characters-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecs']

_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 128,
        "memory": 128,
        "essential": True,
    }
]


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService refuses a serviceName carrying a space and an exclamation mark with its
    documented message, and creates nothing; a name built from the same characters that are
    allowed succeeds."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-svcnamechars-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-svcnamechars-"),
        containerDefinitions=_CONTAINER_DEFS,
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    base = ctx.unique_name("sim2real-behav-ecs-svcnamechars-")
    bad_name = base + " not allowed!"

    error = _error(
        lambda: ecs.create_service(
            cluster=cluster_name, serviceName=bad_name, taskDefinition=td_arn, desiredCount=0
        )
    )
    expected = (
        "InvalidParameterException",
        r"ServiceName must match ^[a-zA-Z0-9\-_]{1,255}$, but was " + bad_name,
    )
    assert error == expected, f"CreateService with a malformed name: expected {expected!r}, got {error!r}"

    # --- the rejected call created no service under the bad name or its sanitized prefix ---
    listed = ecs.list_services(cluster=cluster_name)["serviceArns"]
    assert listed == [], f"a rejected CreateService left a service in the new cluster: {listed!r}"

    # --- positive control: the same prefix, built only from allowed characters, succeeds ---
    good_name = base + "_allowed"
    created = ecs.create_service(
        cluster=cluster_name, serviceName=good_name, taskDefinition=td_arn, desiredCount=0
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=good_name, force=True))
    assert created["serviceName"] == good_name, (
        f"positive control: CreateService returned serviceName {created['serviceName']!r}, expected {good_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
