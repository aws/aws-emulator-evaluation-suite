"""list-identities-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identities-pagination"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentities paginates correctly: a small MaxResults page size returns exactly that many
    identities per page, and walking NextToken eventually surfaces every identity we created."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    created_ids = set()
    for _ in range(5):
        identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
        created_ids.add(identity_id)
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=list(created_ids)))

    first_page = ci.list_identities(IdentityPoolId=pool_id, MaxResults=2)
    assert len(first_page["Identities"]) == 2, (
        f"MaxResults=2 with 5 identities present must fill the page, got "
        f"{len(first_page['Identities'])}"
    )

    seen_ids = {i["IdentityId"] for i in first_page["Identities"]}
    next_token = first_page.get("NextToken")
    for _ in range(50):  # bounded walk
        if not next_token or created_ids <= seen_ids:
            break
        page = ci.list_identities(IdentityPoolId=pool_id, MaxResults=60, NextToken=next_token)
        seen_ids |= {i["IdentityId"] for i in page["Identities"]}
        next_token = page.get("NextToken")

    missing = created_ids - seen_ids
    assert not missing, f"identities never surfaced via pagination: {missing}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
