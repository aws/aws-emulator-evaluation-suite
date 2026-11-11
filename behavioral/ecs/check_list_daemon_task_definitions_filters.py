"""list-daemon-task-definitions-filters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-daemon-task-definitions-filters"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDaemonTaskDefinitions filters by exact family and by familyPrefix,
    returning only the daemon task-def revisions that belong to that family and
    excluding revisions registered under an unrelated family."""

    ecs = ctx.client("ecs")
    if not hasattr(ecs, "register_daemon_task_definition"):
        raise AssertionError("installed botocore/boto3 has no ECS Managed Daemons operations")

    family_a = ctx.unique_name("sim2real-daemon-tdA-")
    family_b = ctx.unique_name("sim2real-daemon-tdB-")

    arn_a1 = _register(ctx, family_a, memory=128)
    arn_a2 = _register(ctx, family_a, memory=256)
    arn_b1 = _register(ctx, family_b, memory=128)

    exact = ecs.list_daemon_task_definitions(family=family_a)["daemonTaskDefinitions"]
    exact_arns = {d["arn"] for d in exact}
    assert exact_arns == {arn_a1, arn_a2}, f"family filter should return exactly the 2 family-A revisions, got {exact_arns}"
    assert arn_b1 not in exact_arns, "family filter leaked an unrelated family's task definition"

    prefixed = ecs.list_daemon_task_definitions(familyPrefix=family_a)["daemonTaskDefinitions"]
    prefixed_arns = {d["arn"] for d in prefixed}
    assert prefixed_arns == {arn_a1, arn_a2}, f"familyPrefix filter mismatch, got {prefixed_arns}"

    last_registered = ecs.list_daemon_task_definitions(family=family_a, revision="LAST_REGISTERED")["daemonTaskDefinitions"]
    assert len(last_registered) == 1, f"LAST_REGISTERED should return exactly 1 entry, got {len(last_registered)}"
    assert last_registered[0]["arn"] == arn_a2, "LAST_REGISTERED should point at the most recently registered revision"

    prefixed_b = ecs.list_daemon_task_definitions(familyPrefix=family_b)["daemonTaskDefinitions"]
    prefixed_b_arns = {d["arn"] for d in prefixed_b}
    assert prefixed_b_arns == {arn_b1}, f"familyPrefix={family_b!r} should return exactly {{{arn_b1!r}}}, got {prefixed_b_arns}"


# ===== helpers =====
def _safe(fn) -> None:
    """Run a delete; a resource already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _register(ctx, family, memory=128):
    ecs = ctx.client("ecs")
    arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "memory": memory,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
