"""list-identity-pools-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identity-pools-reflects-created"
GROUP = "lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created identity pool shows up in ListIdentityPools with the right id/name pairing."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    found = None
    next_token = None
    for _ in range(50):  # bounded pagination walk
        kwargs = {"MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        page = ci.list_identity_pools(**kwargs)
        for entry in page.get("IdentityPools", []):
            if entry["IdentityPoolId"] == pool_id:
                found = entry
                break
        if found or not page.get("NextToken"):
            break
        next_token = page["NextToken"]

    assert found is not None, f"pool {pool_id} not found via ListIdentityPools"
    assert found["IdentityPoolName"] == name, (
        f"expected IdentityPoolName {name!r} in ListIdentityPools entry, got "
        f"{found['IdentityPoolName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
