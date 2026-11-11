"""lookup-developer-identity-mismatch-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "lookup-developer-identity-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LookupDeveloperIdentity given BOTH an IdentityId and a DeveloperUserIdentifier that don't
    actually belong together must reject with ResourceConflictException, not silently return
    whichever value it 'trusts' more."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    user_a = ctx.unique_name("user-a-")
    user_b = ctx.unique_name("user-b-")
    identity_a = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_a}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_a]))
    identity_b = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_b}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_b]))
    assert identity_a != identity_b

    # Positive control: the correctly-matched pair resolves, proving the account and
    # credentials are otherwise healthy for this call shape.
    control = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_a, DeveloperUserIdentifier=user_a,
        MaxResults=10,
    )
    assert control["IdentityId"] == identity_a, f"positive control did not resolve: {control!r}"

    # user_a belongs to identity_a, not identity_b -- deliberately cross them. MaxResults must be
    # passed explicitly: real AWS defaults an omitted value to 0 server-side.
    code, message = _error(
        lambda: ci.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=identity_b, DeveloperUserIdentifier=user_a,
            MaxResults=10,
        )
    )
    # Real AWS rejects the mismatched pair as ResourceConflictException.
    assert code == "ResourceConflictException", f"got {code!r}"
    expected = "The provided user identifier and identity id do not match."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected call created no binding between identity_b and user_a.
    after = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_b, MaxResults=10
    )
    assert user_a not in after.get("DeveloperUserIdentifierList", []), (
        f"the rejected mismatched lookup left user_a bound to identity_b: {after!r}"
    )


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
