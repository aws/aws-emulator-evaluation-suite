"""lookup-developer-identity-by-user-identifier."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lookup-developer-identity-by-user-identifier"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupDeveloperIdentity resolves a developer user identifier back to its identity."""
    ci = ctx.client("cognito-identity")
    dev_provider = "login.sim2real.devlookup"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user_id = ctx.unique_name("user-lookup-")
    identity_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_id}
    )["IdentityId"]

    # MaxResults is optional per the API model, but real AWS rejects LookupDeveloperIdentity
    # calls that omit it with "ValidationException: Value '0' at 'maxResults' failed to satisfy
    # constraint..." — pass an explicit, in-range value to avoid that spurious rejection.
    resp = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=1
    )
    assert resp["IdentityId"] == identity_id, (
        f"expected lookup-by-user-identifier to resolve to {identity_id}, got {resp['IdentityId']}"
    )
    assert dev_user_id in resp.get("DeveloperUserIdentifierList", []), (
        f"expected {dev_user_id} in {resp.get('DeveloperUserIdentifierList')}"
    )

    resp_by_id = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=1
    )
    assert resp_by_id["IdentityId"] == identity_id, (
        f"expected lookup-by-identity-id to echo {identity_id}, got {resp_by_id['IdentityId']}"
    )
    assert dev_user_id in resp_by_id.get("DeveloperUserIdentifierList", []), (
        f"expected {dev_user_id} in {resp_by_id.get('DeveloperUserIdentifierList')} "
        "on the reverse lookup by IdentityId"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
