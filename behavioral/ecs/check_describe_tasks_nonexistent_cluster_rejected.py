"""describe-tasks-nonexistent-cluster-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-tasks-nonexistent-cluster-rejected"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTasks on a never-created cluster fails with ClusterNotFoundException, while the
    same call on an existing cluster is answered normally, so the rejection is keyed on
    cluster existence."""
    ecs = ctx.client("ecs")
    fake_task_id = "0000000000000000000000000000aaaa"

    real_cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))[
        "cluster"
    ]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster))

    # Positive control: the same call, against a cluster that genuinely exists,
    # must not raise ClusterNotFoundException — it answers with the task simply
    # missing from the cluster.
    control_resp = ecs.describe_tasks(cluster=real_cluster, tasks=[fake_task_id])
    assert not control_resp["tasks"], f"expected no tasks, got {control_resp['tasks']}"
    failures = control_resp["failures"]
    assert len(failures) == 1, f"expected exactly one failure, got {failures}"
    assert failures[0]["reason"] == "MISSING", f"expected MISSING, got {failures[0]}"

    bogus_cluster = ctx.unique_name("sim2real-behav-nosuchcluster-")
    code, message = _error(
        lambda: ecs.describe_tasks(
            cluster=bogus_cluster,
            tasks=[fake_task_id],
        )
    )
    assert code == "ClusterNotFoundException", f"expected ClusterNotFoundException, got {code}"
    assert message == "Cluster not found.", f"unexpected message: {message!r}"


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
