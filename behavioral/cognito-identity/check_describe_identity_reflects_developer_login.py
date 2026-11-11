"""describe-identity-reflects-developer-login."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-identity-reflects-developer-login"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a developer-authenticated login is registered, DescribeIdentity's Logins lists the provider name."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real-check": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user = ctx.unique_name("user-")
    resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )
    identity_id = resp["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    described = ci.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id
    assert described["Logins"] == [dev_provider], (
        f"expected Logins=[{dev_provider!r}], got {described['Logins']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
