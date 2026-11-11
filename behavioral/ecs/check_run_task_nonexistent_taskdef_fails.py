"""run-task-nonexistent-taskdef-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-nonexistent-taskdef-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask referencing a task definition that was never registered
    must fail (overly-permissive check)."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    bogus_td = f"{ctx.unique_name('sim2real-behav-ecs-taskdef-missing-')}:1"

    try:
        resp = ecs.run_task(
            cluster=cluster["clusterName"], taskDefinition=bogus_td
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"RunTask with a never-registered task definition SUCCEEDED and returned {resp!r}")
    assert code == "ClientException", f"expected ClientException for a never-registered task definition, got {code}"
    assert message == "TaskDefinition not found.", f"refusal message {message!r}"

    tasks = ecs.list_tasks(cluster=cluster["clusterName"])["taskArns"]
    assert tasks == [], f"expected no task launched from the rejected RunTask call, found {tasks}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
