"""task-definition-registered-at-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "task-definition-registered-at-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A task definition's registeredAt is fixed at registration: repeated DescribeTaskDefinition
    calls return the identical timestamp, not a fresh "now" per read.
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-regat-")

    t_before = time.time()
    register = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 64,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    t_after = time.time()
    task_def_arn = register["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    registered_at_1 = register["taskDefinition"]["registeredAt"]

    # The frozen value must also be a real point in the registration window, not merely
    # frozen at an arbitrary constant (e.g. a stub that always returns epoch 0).
    lower_bound = t_before - 5.0
    upper_bound = t_after + 5.0
    ts = registered_at_1.timestamp()
    assert lower_bound <= ts <= upper_bound, (
        f"registeredAt {ts} ({registered_at_1!r}) not within the actual registration window "
        f"[{lower_bound}, {upper_bound}]"
    )

    described_first = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    assert described_first["registeredAt"] == registered_at_1, (
        f"registeredAt from the first independent DescribeTaskDefinition "
        f"({described_first['registeredAt']!r}) must equal the value from RegisterTaskDefinition "
        f"({registered_at_1!r})"
    )

    _poll_timestamp_stable(ctx, task_def_arn, registered_at_1, window_s=3.0, interval_s=0.5)


# ===== helpers =====
def _poll_timestamp_stable(
    ctx, task_def_arn: str, expected_registered_at, window_s: float, interval_s: float
) -> None:
    """Repeatedly re-read DescribeTaskDefinition across a real elapsed window,
    asserting registeredAt never drifts from the value captured at registration
    (i.e. it is not being freshly re-derived on each read)."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + window_s
    checks = 0
    while time.monotonic() < deadline:
        described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
        assert described["registeredAt"] == expected_registered_at, (
            f"registeredAt drifted from {expected_registered_at} to "
            f"{described['registeredAt']} on poll {checks}"
        )
        checks += 1
        time.sleep(interval_s)
    assert checks >= 2, "did not get enough polls in to confirm timestamp stability"


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
