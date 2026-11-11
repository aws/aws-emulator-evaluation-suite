"""daemon-revision-numbers-strictly-increase."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "daemon-revision-numbers-strictly-increase"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Successive RegisterDaemonTaskDefinition calls to the same family produce strictly
    increasing, never-reused revision numbers -- including across a delete: removing an
    older revision must not free its number for a later registration to reclaim."""

    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-daemon-td-")

    def _register(memory: int) -> str:
        arn = ecs.register_daemon_task_definition(
            family=family,
            containerDefinitions=[
                {"name": "c", "image": "public.ecr.aws/docker/library/busybox:1.36", "essential": True, "memory": memory}
            ],
            tags=[{"key": "sim2real", "value": "yes"}],
        )["daemonTaskDefinitionArn"]
        ctx.on_cleanup(lambda a=arn: _delete_best_effort(ecs, a))
        return arn

    def _revision(arn: str) -> int:
        return ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]["revision"]

    arn1 = _register(64)
    rev1 = _revision(arn1)
    assert rev1 == 1, f"expected the first registration in a fresh family to be revision 1, got {rev1}"

    arn2 = _register(128)
    rev2 = _revision(arn2)
    assert rev2 == rev1 + 1, f"expected revision {rev1 + 1} after a second registration, got {rev2}"

    # Delete the OLDER revision, then prove its number is never reused: the next
    # registration to this family must still advance past the highest number ever issued,
    # not backfill the gap the delete just opened.
    deleted_arn = ecs.delete_daemon_task_definition(daemonTaskDefinition=arn1)["daemonTaskDefinitionArn"]
    assert deleted_arn == arn1, f"DeleteDaemonTaskDefinition returned {deleted_arn}, expected {arn1}"

    deleted_desc = _poll_until(
        lambda: ecs.describe_daemon_task_definition(daemonTaskDefinition=arn1)["daemonTaskDefinition"],
        lambda d: d["status"] != "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert deleted_desc["status"] in ("DELETE_IN_PROGRESS", "INACTIVE"), (
        f"expected revision {rev1} to leave ACTIVE after delete, got {deleted_desc['status']}"
    )

    arn3 = _register(192)
    rev3 = _revision(arn3)
    assert rev3 == rev2 + 1, (
        f"deleting revision {rev1} must not free its number for reuse: expected revision {rev2 + 1} "
        f"after the delete, got {rev3}"
    )

    revision_numbers = [rev1, rev2, rev3]
    assert revision_numbers == sorted(revision_numbers), (
        f"daemon task definition revision numbers did not strictly increase: {revision_numbers}"
    )
    assert len(set(revision_numbers)) == len(revision_numbers), (
        f"expected strictly distinct revision numbers, got duplicates: {revision_numbers}"
    )

    arns = [arn1, arn2, arn3]
    assert len(set(arns)) == len(arns), f"expected a distinct daemonTaskDefinitionArn per revision, got: {arns}"


# ===== helpers =====
def _delete_best_effort(ecs, arn: str) -> None:
    """Delete the daemon task definition; one that no longer exists is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
