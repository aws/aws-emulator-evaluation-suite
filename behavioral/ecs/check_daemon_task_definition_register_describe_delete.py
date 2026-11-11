"""daemon-task-definition-register-describe-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "daemon-task-definition-register-describe-delete"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered daemon task definition is describable (by ARN and family:revision) with its
    container spec; after DeleteDaemonTaskDefinition it stays describable but is no longer ACTIVE.
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-daemon-td-")

    registered = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "memory": 128,
                "command": ["sh", "-c", "sleep 3600"],
            }
        ],
    )
    td_arn = registered["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_best_effort(ecs, td_arn))

    described = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]
    assert described["daemonTaskDefinitionArn"] == td_arn
    assert described["containerDefinitions"][0]["name"] == "agent"
    assert described["containerDefinitions"][0]["image"] == "public.ecr.aws/docker/library/busybox:1.36"

    family_revision_ref = f"{family}:{described['revision']}"
    described_by_family = ecs.describe_daemon_task_definition(daemonTaskDefinition=family_revision_ref)[
        "daemonTaskDefinition"
    ]
    assert described_by_family["daemonTaskDefinitionArn"] == td_arn

    ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)

    # AWS reports DELETE_IN_PROGRESS for well over 300 s before a terminal status, so assert
    # only that the definition leaves ACTIVE and stays describable.
    def _status_after_delete():
        return ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]["status"]

    status_after_delete = _poll_until(_status_after_delete, lambda s: s != "ACTIVE", timeout_s=60, interval_s=3)
    described_after_delete = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]
    assert described_after_delete["daemonTaskDefinitionArn"] == td_arn
    assert status_after_delete in ("DELETE_IN_PROGRESS", "INACTIVE", "DELETED"), (
        f"expected delete to mark the daemon task definition non-active (pending deletion or "
        f"terminal) while remaining describable, got {status_after_delete!r}"
    )


def _delete_best_effort(ecs, td_arn):
    """Delete the daemon task definition; one already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
