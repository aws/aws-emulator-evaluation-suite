"""delete-daemon-task-definition-already-deleted-invalid-parameter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-daemon-task-definition-already-deleted-invalid-parameter"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a successful first delete, a repeat DeleteDaemonTaskDefinition on a revision confirmed
    non-ACTIVE succeeds idempotently; DescribeDaemonTaskDefinition keeps describing the revision
    and never reports it ACTIVE again."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-daemon-td-")

    try:
        reg = ecs.register_daemon_task_definition(
            family=family,
            containerDefinitions=[
                {
                    "name": "agent",
                    "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "essential": True,
                    "memory": 128,
                    "command": ["sleep", "60"],
                }
            ],
            tags=[{"key": "sim2real", "value": "true"}],
        )
    except ClientError as err:
        raise AssertionError(
            f"RegisterDaemonTaskDefinition unavailable/unauthorized: {err.response['Error']['Code']}"
        )

    arn = reg["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)))

    # positive control: deleting the freshly-registered family succeeds
    del_resp = ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)
    assert del_resp.get("daemonTaskDefinitionArn") == arn

    # confirm the revision has actually left ACTIVE before probing a repeat delete against it --
    # firing the repeat immediately would race the async status transition and prove nothing about
    # "delete an already-deleted revision" specifically
    after = _poll_until(
        lambda: ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"],
        lambda d: d["status"] != "ACTIVE",
        timeout_s=60.0,
    )
    assert after["daemonTaskDefinitionArn"] == arn
    assert after["family"] == family
    assert after["status"] in ("DELETE_IN_PROGRESS", "INACTIVE", "DELETED"), (
        f"expected the deleted revision to remain describable in a non-ACTIVE state, "
        f"got {after['status']!r}"
    )

    # re-delete a *confirmed* non-ACTIVE revision and record what real AWS actually does with it
    second_del_resp = ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)
    assert second_del_resp.get("daemonTaskDefinitionArn") == arn, (
        f"expected the repeat delete of an already non-ACTIVE revision to succeed idempotently, "
        f"got {second_del_resp!r}"
    )

    # describe never resurrects ACTIVE after the repeat delete
    still_after = ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]
    assert still_after["daemonTaskDefinitionArn"] == arn
    assert still_after["status"] != "ACTIVE", f"repeat delete resurrected ACTIVE: {still_after['status']!r}"


# ===== helpers =====


def _ignore_missing(fn) -> None:
    """Run a teardown step; return only when its target is already gone, raise anything else."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
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
