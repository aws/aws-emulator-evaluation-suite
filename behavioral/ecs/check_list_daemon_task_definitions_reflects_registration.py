"""list-daemon-task-definitions-reflects-registration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-daemon-task-definitions-reflects-registration"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly registered daemon task definition's ARN appears in ListDaemonTaskDefinitions,
    and disappears once it's deleted."""
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
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td_arn = registered["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe_delete_daemon_td(ecs, td_arn))

    def _all_arns():
        arns = []
        paginator_kwargs = {}
        while True:
            page = ecs.list_daemon_task_definitions(**paginator_kwargs)
            # The list field's exact key isn't guaranteed by pinned assumptions here; pick the
            # first list-valued field in the response (excluding metadata/pagination) instead of
            # hardcoding one that may not match the live API shape.
            list_key = next(
                (k for k, v in page.items() if k not in ("ResponseMetadata", "nextToken") and isinstance(v, list)),
                None,
            )
            if list_key is None:
                break
            for item in page[list_key]:
                if isinstance(item, str):
                    arns.append(item)
                elif isinstance(item, dict):
                    arn = item.get("daemonTaskDefinitionArn") or item.get("arn")
                    if arn:
                        arns.append(arn)
            token = page.get("nextToken")
            if not token:
                break
            paginator_kwargs["nextToken"] = token
        return arns

    arns_after_register = _all_arns()
    assert td_arn in arns_after_register, f"{td_arn} missing from ListDaemonTaskDefinitions after registration"

    ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)

    arns_after_delete = _poll_until(_all_arns, lambda arns: td_arn not in arns, timeout_s=60, interval_s=3)
    assert td_arn not in arns_after_delete, f"{td_arn} still present in ListDaemonTaskDefinitions after deletion"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe_delete_daemon_td(ecs, arn):
    """Delete the daemon task definition; one already gone is done, any other error raises."""
    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
