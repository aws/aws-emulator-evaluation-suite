"""describe-services-duplicate-name-in-list-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-services-duplicate-name-in-list-rejected"
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
    """DescribeServices refuses a request that names the same service twice, while the identical
    single-name call it is built from succeeds."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-descsvcdup-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-descsvcdup-"),
        containerDefinitions=_CONTAINER_DEFS,
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    service_name = ctx.unique_name("sim2real-behav-ecs-descsvcdup-")
    created = ecs.create_service(
        cluster=cluster_name, serviceName=service_name, taskDefinition=td_arn, desiredCount=0
    )["service"]
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    )

    # --- positive control: the real name, once, is found ---
    single = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
    assert single and single[0]["serviceArn"] == created["serviceArn"], (
        f"positive control: DescribeServices([{service_name!r}]) did not find it: {single!r}"
    )

    # --- negative: the same real name listed twice is refused outright ---
    error = _error(
        lambda: ecs.describe_services(cluster=cluster_name, services=[service_name, service_name])
    )
    expected = ("InvalidParameterException", "Malformed request with duplicate service names.")
    assert error == expected, f"DescribeServices with a duplicated name: expected {expected!r}, got {error!r}"

    # --- the rejected call left the service untouched ---
    after = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
    assert after and after[0]["status"] == "ACTIVE", (
        f"a rejected DescribeServices changed the service's status: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
