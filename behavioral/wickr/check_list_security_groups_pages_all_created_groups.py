"""list-security-groups-pages-all-created-groups."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-security-groups-pages-all-created-groups"
GROUP = "security-groups"
SERVICES = ["wickr"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found`` codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecurityGroups, paged 3 at a time, returns every created group exactly once,
    not truncated to one page and not missing or duplicating any member.

    Reference: https://docs.aws.amazon.com/wickr/latest/APIReference/API_ListSecurityGroups.html
    """
    wickr = ctx.client("wickr", region="us-east-1")
    network_name = ctx.unique_name("sim2real")[:20]

    network = wickr.create_network(networkName=network_name, accessLevel="STANDARD")
    network_id = network["networkId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_network(networkId=network_id), "ForbiddenError"))

    default_id = wickr.list_security_groups(networkId=network_id)["securityGroups"][0]["id"]
    created_ids = {default_id}
    for _ in range(7):
        name = ctx.unique_name("sim2real-probe-sg-")
        sg = wickr.create_security_group(
            networkId=network_id, name=name, securityGroupSettings={"federationMode": 1}
        )
        created_ids.add(sg["securityGroup"]["id"])

    seen_ids: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {
            "networkId": network_id,
            "maxResults": 3,
            "sortFields": "id",
            "sortDirection": "ASC",
        }
        if next_token:
            kwargs["nextToken"] = next_token
        page = wickr.list_security_groups(**kwargs)
        seen_ids.extend(g["id"] for g in page["securityGroups"])
        pages += 1
        next_token = page.get("nextToken")
        if not next_token:
            break
        assert pages < 20, "pagination did not terminate within 20 pages"

    assert pages >= 3, f"expected at least 3 pages of 3 for 8 groups, got {pages}"
    assert len(seen_ids) == len(set(seen_ids)), (
        f"ListSecurityGroups returned a duplicate across pages: {seen_ids!r}"
    )
    assert set(seen_ids) == created_ids, (
        f"paged ListSecurityGroups returned {sorted(seen_ids)}, expected exactly {sorted(created_ids)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
