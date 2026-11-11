"""create-system-same-client-token-is-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-system-same-client-token-is-idempotent"
GROUP = 'idempotency'
SERVICES = ['resiliencehubv2']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSystem called twice with the same clientToken and the same name returns the
    identical system, not a second resource."""
    rh = ctx.client("resiliencehubv2")
    name = ctx.unique_name("sim2real-behav-rhv2-")
    token = ctx.unique_name("sim2real-behav-rhv2-tok-")

    first = rh.create_system(name=name, clientToken=token)["system"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_system(systemArn=first["systemArn"]), "ResourceNotFoundException"
    ))

    second = rh.create_system(name=name, clientToken=token)["system"]
    assert second["systemArn"] == first["systemArn"], (
        f"a repeated CreateSystem with the same clientToken and name must return the same "
        f"systemArn {first['systemArn']!r}, got {second['systemArn']!r}"
    )
    assert second["systemId"] == first["systemId"], (
        f"a repeated CreateSystem with the same clientToken must return the same systemId "
        f"{first['systemId']!r}, got {second['systemId']!r}"
    )

    page = rh.list_systems()["systemSummaries"]
    matching = [s for s in page if s["name"] == name]
    assert len(matching) == 1, (
        f"ListSystems must show exactly one system named {name!r} after two idempotent "
        f"creates, found {len(matching)}: {matching!r}"
    )
    assert matching[0]["systemArn"] == first["systemArn"], (
        f"the listed system's ARN must be {first['systemArn']!r}, got {matching[0]['systemArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
