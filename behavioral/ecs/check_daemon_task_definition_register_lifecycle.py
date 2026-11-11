"""daemon-task-definition-register-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "daemon-task-definition-register-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterDaemonTaskDefinition creates an ACTIVE revision 1; delete moves it off ACTIVE, a
    second delete echoes the same ARN, and it leaves the default listing but appears when the
    listing is filtered by its current status."""

    ecs = ctx.client("ecs")
    if not hasattr(ecs, "register_daemon_task_definition"):
        raise AssertionError("installed botocore/boto3 has no ECS Managed Daemons operations")

    family = ctx.unique_name("sim2real-daemon-td-")
    arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "memory": 128,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)))

    described = ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]
    assert described["status"] == "ACTIVE", f"expected ACTIVE, got {described['status']}"
    assert described["revision"] == 1, f"expected revision 1, got {described['revision']}"
    assert described["family"] == family, f"expected family {family!r}, got {described['family']!r}"

    deleted_arn = ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinitionArn"]
    assert deleted_arn == arn, f"expected delete response to echo {arn!r}, got {deleted_arn!r}"

    # Unlike regular task definitions, a deleted daemon task definition can rest in
    # DELETE_IN_PROGRESS for minutes, so only the move off ACTIVE is awaited.
    after = _poll_until(
        lambda: ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"],
        lambda d: d["status"] != "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert after["status"] in ("DELETE_IN_PROGRESS", "INACTIVE"), (
        f"expected DELETE_IN_PROGRESS or INACTIVE, got {after['status']}"
    )

    second_deleted_arn = ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinitionArn"]
    assert second_deleted_arn == arn, (
        f"expected a second delete of the already non-ACTIVE revision to idempotently echo "
        f"{arn!r}, got {second_deleted_arn!r}"
    )
    still_after = ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]
    assert still_after["status"] != "ACTIVE", (
        f"a redundant delete must not resurrect the revision to ACTIVE, got {still_after['status']!r}"
    )

    default_listing = ecs.list_daemon_task_definitions(familyPrefix=family)["daemonTaskDefinitions"]
    assert arn not in [d["arn"] for d in default_listing], (
        "a non-ACTIVE daemon task definition leaked into the default (ACTIVE-only) listing"
    )

    # status="ALL" is rejected here with InvalidParameterException, so filter by the current status.
    status_listing = ecs.list_daemon_task_definitions(familyPrefix=family, status=after["status"])[
        "daemonTaskDefinitions"
    ]
    assert arn in [d["arn"] for d in status_listing], (
        f"deleted daemon task definition missing from status={after['status']!r} listing"
    )


def _safe(fn) -> None:
    """Run a teardown delete: a resource already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if "does not exist" not in err.response["Error"].get("Message", ""):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
