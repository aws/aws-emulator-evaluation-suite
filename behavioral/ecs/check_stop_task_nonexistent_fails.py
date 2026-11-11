"""stop-task-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-task-nonexistent-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopTask on a task ARN that was never created must fail
    (overly-permissive check)."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    bogus_task = (
        f"arn:aws:ecs:{ctx.region}:111122223333:task/"
        f"{cluster['clusterName']}/00000000000000000000000000000000"
    )
    try:
        result = ecs.stop_task(cluster=cluster["clusterName"], task=bogus_task)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"StopTask on a never-created task ARN succeeded and returned {result!r}")
    assert code == "InvalidParameterException", f"unexpected error code: {code}"
    assert message == "AccountIDs mismatch", f"unexpected error message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
