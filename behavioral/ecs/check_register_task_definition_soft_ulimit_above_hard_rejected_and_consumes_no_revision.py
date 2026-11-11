"""register-task-definition-soft-ulimit-above-hard-rejected-and-consumes-no-revision."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-task-definition-soft-ulimit-above-hard-rejected-and-consumes-no-revision"
GROUP = "container-runtime"
SERVICES = ["ecs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A nofile ulimit with softLimit > hardLimit is refused with ClientException.

    Nothing is registered, and the next valid registrations are revisions 1 and 2.
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-ulim-")
    registered: list[str] = []

    def _drop():
        for arn in registered:
            ecs.deregister_task_definition(taskDefinition=arn)
        if registered:
            ecs.delete_task_definitions(taskDefinitions=list(registered))

    ctx.on_cleanup(_drop)

    def _register(soft: int, hard: int) -> dict:
        td = ecs.register_task_definition(
            family=family, networkMode="awsvpc", requiresCompatibilities=["FARGATE"],
            cpu="256", memory="512",
            containerDefinitions=[{
                "name": "app", "image": _IMAGE, "essential": True,
                "ulimits": [{"name": "nofile", "softLimit": soft, "hardLimit": hard}],
            }],
        )["taskDefinition"]
        registered.append(td["taskDefinitionArn"])
        return td

    def _family_revisions() -> list[str]:
        arns: list[str] = []
        for status in ("ACTIVE", "INACTIVE"):
            for page in ecs.get_paginator("list_task_definitions").paginate(
                    familyPrefix=family, status=status):
                arns.extend(page["taskDefinitionArns"])
        return sorted(arns)

    # --- Break exactly one thing: soft above hard.
    try:
        bad = _register(8192, 4096)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"softLimit 8192 > hardLimit 4096 was ACCEPTED as {bad['taskDefinitionArn']!r}")
    assert code == "ClientException", f"soft > hard was refused with {code!r} ({message!r})"
    assert message == "Soft limit exceeds hard limit for ulimit nofile", f"refusal message {message!r}"
    assert _family_revisions() == [], f"the refused registration left {_family_revisions()!r}"

    # --- Positive control: the same family with soft <= hard registers as revision 1, then 2.
    first = _register(4096, 8192)
    assert first["revision"] == 1, (
        f"first valid registration after the refusal is revision {first['revision']!r}, expected 1 "
        f"-- the refused call consumed a revision"
    )
    stored = first["containerDefinitions"][0]["ulimits"]
    assert stored == [{"name": "nofile", "softLimit": 4096, "hardLimit": 8192}], stored
    second = _register(8192, 8192)
    assert second["revision"] == 2, f"second valid registration is revision {second['revision']!r}"
    assert _family_revisions() == sorted(registered), (
        f"family lists {_family_revisions()!r}, expected exactly {sorted(registered)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
