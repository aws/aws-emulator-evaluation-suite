"""daemon-task-definition-delete-then-describe-inactive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "daemon-task-definition-delete-then-describe-inactive"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDaemonTaskDefinition marks the revision non-ACTIVE without purging it."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-daemon-td-")

    td_arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "cpu": 128,
                "memory": 256,
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_best_effort(ecs, td_arn))

    before = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]
    assert before["status"] == "ACTIVE"

    delete_resp = ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)
    assert delete_resp["daemonTaskDefinitionArn"] == td_arn

    # the revision must still be describable (not purged) but no longer ACTIVE
    after = _poll_until(
        lambda: ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"],
        lambda d: d["status"] != "ACTIVE",
        timeout_s=60.0,
    )
    assert after["daemonTaskDefinitionArn"] == td_arn, "deleted revision must remain describable, not purged"
    assert after["family"] == family
    # DaemonTaskDefinitionStatus (per the Smithy model) is {ACTIVE, DELETE_IN_PROGRESS, DELETED} --
    # there is no "INACTIVE" member for this newer API, unlike the classic TaskDefinition status
    # enum. After DeleteDaemonTaskDefinition the revision stays DELETE_IN_PROGRESS for minutes;
    # DELETED is the terminal value if the transition settles within the poll.
    assert after["status"] in ("DELETE_IN_PROGRESS", "DELETED"), f"unexpected post-delete status: {after['status']}"

    # it must also disappear from the default ACTIVE-only listing for the family
    active_only = ecs.list_daemon_task_definitions(familyPrefix=family)["daemonTaskDefinitions"]
    active_arns = {d["arn"] for d in active_only}
    assert td_arn not in active_arns, "deleted revision must not appear in the default ACTIVE listing"

    # but it must still appear when explicitly asking for every status: the model documents
    # status=ALL as listing daemon task definitions regardless of status (AWS accepts ALL only
    # with revision=LAST_REGISTERED; the family has the one revision).
    listing_kwargs = {"familyPrefix": family, "status": "ALL", "revision": "LAST_REGISTERED"}
    inactive_listing = _poll_until(
        lambda: ecs.list_daemon_task_definitions(**listing_kwargs)["daemonTaskDefinitions"],
        lambda entries: td_arn in {d["arn"] for d in entries},
        timeout_s=120.0,
        interval_s=5.0,
    )
    inactive_arns = {d["arn"] for d in inactive_listing}
    assert td_arn in inactive_arns, (
        f"deleted revision must still be enumerable via ListDaemonTaskDefinitions (tried {listing_kwargs})"
    )


# ===== helpers =====

def _delete_best_effort(ecs, td_arn):
    """Delete the daemon task definition; one already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
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
