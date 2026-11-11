"""task-ops-on-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
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
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RunTask, StartTask, StopTask, DescribeTasks and ListTasks on a nonexistent cluster return
    ClusterNotFoundException; a positive control on a real cluster shows the failure is specific
    to the missing cluster.
    """
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    resource_tags = [{"key": "sim2real-behav", "value": CHECK}]
    td = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS, tags=resource_tags
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    real_cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=real_cluster, tags=resource_tags)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster))

    def fake_task_arn(cluster: str) -> str:
        return (
            f"arn:aws:ecs:{ctx.region}:{account_id}:task/{cluster}/"
            "00000000000000000000000000000000"
        )

    def fake_ci_arn(cluster: str) -> str:
        return (
            f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{cluster}/"
            "00000000000000000000000000000000"
        )

    # Positive control: the identical calls against a REAL cluster must never
    # answer ClusterNotFoundException. Without this, the negative assertions
    # below cannot tell "correctly rejects a missing cluster" from "rejects
    # every task operation regardless of cluster".
    controls = [
        ("RunTask", lambda: ecs.run_task(cluster=real_cluster, taskDefinition=td_arn)),
        (
            "StartTask",
            lambda: ecs.start_task(
                cluster=real_cluster, taskDefinition=td_arn,
                containerInstances=[fake_ci_arn(real_cluster)],
            ),
        ),
        ("StopTask", lambda: ecs.stop_task(cluster=real_cluster, task=fake_task_arn(real_cluster))),
    ]
    for label, call in controls:
        code = None
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
        assert code != "ClusterNotFoundException", f"{label} positive control: got {code}"

    described = ecs.describe_tasks(cluster=real_cluster, tasks=[fake_task_arn(real_cluster)])
    assert described.get("failures"), f"DescribeTasks positive control: {described}"

    listed = ecs.list_tasks(cluster=real_cluster)
    assert listed["taskArns"] == [], f"ListTasks positive control: {listed['taskArns']}"

    # Negative: the identical calls against a cluster that has never existed.
    not_found = ("ClusterNotFoundException", "Cluster not found.")

    error = _error(lambda: ecs.run_task(cluster=bogus_cluster, taskDefinition=td_arn))
    assert error == not_found, f"RunTask: got {error!r}"

    error = _error(
        lambda: ecs.start_task(
            cluster=bogus_cluster, taskDefinition=td_arn,
            containerInstances=[fake_ci_arn(bogus_cluster)],
        )
    )
    assert error == not_found, f"StartTask: got {error!r}"

    error = _error(
        lambda: ecs.stop_task(cluster=bogus_cluster, task=fake_task_arn(bogus_cluster))
    )
    assert error == not_found, f"StopTask: got {error!r}"

    error = _error(
        lambda: ecs.describe_tasks(cluster=bogus_cluster, tasks=[fake_task_arn(bogus_cluster)])
    )
    assert error == not_found, f"DescribeTasks: got {error!r}"

    error = _error(lambda: ecs.list_tasks(cluster=bogus_cluster))
    assert error == not_found, f"ListTasks: got {error!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
