"""task-definition-deregister-transitions-to-inactive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "task-definition-deregister-transitions-to-inactive"
GROUP = "state"
SERVICES = ["ecs"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTaskDefinition flips status ACTIVE->INACTIVE and stamps deregisteredAt;
    the definition remains describable while INACTIVE."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-fam-")

    registered = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))

    assert registered["status"] == "ACTIVE", f"expected ACTIVE on register, got {registered['status']}"

    deregistered = ecs.deregister_task_definition(taskDefinition=arn)["taskDefinition"]
    assert deregistered["status"] == "INACTIVE", f"expected INACTIVE, got {deregistered['status']}"

    # deregisteredAt is stamped asynchronously on some accounts/regions; poll describe
    # until it shows up rather than assuming it's present on the DeregisterTaskDefinition
    # response itself.
    described = _poll_until(
        lambda: ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"],
        lambda td: "deregisteredAt" in td,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert described["status"] == "INACTIVE", (
        f"expected independent describe to read back INACTIVE, got {described['status']}"
    )
    assert described["family"] == family, f"expected family {family!r}, got {described['family']!r}"
    assert described["revision"] == registered["revision"], (
        f"expected revision {registered['revision']}, got {described['revision']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
