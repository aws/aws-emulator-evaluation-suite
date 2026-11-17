"""describe-tasks-id-list-bounds-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-tasks-id-list-bounds-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED with {result!r}")


def _task_id():
    return uuid.uuid4().hex


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTasks refuses an empty tasks list and a list over 100 entries with their documented
    messages, while a 100-entry list is accepted and reported as missing."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-desctasks-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    # --- positive control: exactly 100 ids (the documented cap) is accepted ---
    at_cap = [_task_id() for _ in range(100)]
    control = ecs.describe_tasks(cluster=cluster_arn, tasks=at_cap)
    assert control["tasks"] == [], f"positive control: expected no real tasks, got {control['tasks']!r}"
    missing = {f["arn"].rsplit("/", 1)[-1] for f in control["failures"]}
    assert missing == set(at_cap), (
        f"positive control: expected all {len(at_cap)} ids reported MISSING, got {missing!r}"
    )

    # --- negative: one id over the cap is refused outright, nothing evaluated ---
    over_cap = at_cap + [_task_id()]
    error = _error(lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=over_cap))
    expected = ("InvalidParameterException", "taskIds can have at most 100 items.")
    assert error == expected, f"DescribeTasks over the cap: expected {expected!r}, got {error!r}"

    # --- negative: an empty tasks list is refused, not treated as "describe nothing" ---
    error = _error(lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[]))
    expected = ("InvalidParameterException", "Tasks cannot be empty.")
    assert error == expected, f"DescribeTasks with an empty list: expected {expected!r}, got {error!r}"

    # --- the rejected calls left the well-formed positive control's answer unaffected ---
    replay = ecs.describe_tasks(cluster=cluster_arn, tasks=at_cap)
    replay_missing = {f["arn"].rsplit("/", 1)[-1] for f in replay["failures"]}
    assert replay_missing == set(at_cap), (
        f"a rejected call changed the well-formed one's answer: {replay_missing!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
