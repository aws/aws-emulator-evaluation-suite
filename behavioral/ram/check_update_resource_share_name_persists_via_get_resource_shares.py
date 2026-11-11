"""update-resource-share-name-persists-via-get-resource-shares."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-share-name-persists-via-get-resource-shares"
GROUP = "resource-share-lifecycle"
SERVICES = ["ram"]


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
    """UpdateResourceShare's renamed value is what a later, independent
    GetResourceShares read returns, not just the mutation's own response."""
    ram = ctx.client("ram")

    name = ctx.unique_name("sim2real-ram-upd-")
    share = ram.create_resource_share(
        name=name, tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )
    assert share["name"] == name, f"expected initial name {name!r}, got {share['name']!r}"

    renamed = name + "-renamed"
    updated = ram.update_resource_share(resourceShareArn=share_arn, name=renamed)["resourceShare"]
    assert updated["name"] == renamed, (
        f"UpdateResourceShare's own response carries {updated['name']!r}, expected {renamed!r}"
    )

    got = ram.get_resource_shares(resourceShareArns=[share_arn], resourceOwner="SELF")[
        "resourceShares"
    ][0]
    assert got["name"] == renamed, (
        f"an independent GetResourceShares read returned {got['name']!r}, expected {renamed!r}"
    )
    assert got["status"] == "ACTIVE", f"expected the share to remain ACTIVE, got {got['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
