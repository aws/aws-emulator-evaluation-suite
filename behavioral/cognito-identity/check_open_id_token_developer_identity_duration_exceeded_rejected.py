"""open-id-token-developer-identity-duration-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "open-id-token-developer-identity-duration-exceeded-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TokenDuration above the 86400 s maximum is refused with ValidationException and the exact
    message, LookupDeveloperIdentity for that user answers NotAuthorizedException, and a valid call
    on the same pool creates an identity LookupDeveloperIdentity resolves."""
    cid = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    bad_user = ctx.unique_name("sim2real-user-")
    code, message = _error(
        lambda: cid.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={dev_provider: bad_user}, TokenDuration=86401
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value '86401' at 'tokenDuration' failed to satisfy "
        "constraint: Member must have value less than or equal to 86400"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected call never registered bad_user as a developer identity.
    lookup_code, lookup_message = _error(
        lambda: cid.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=bad_user, MaxResults=10
        )
    )
    assert lookup_code == "NotAuthorizedException", (
        f"expected the rejected TokenDuration call to leave no identity behind, got {lookup_code}"
    )
    assert lookup_message == "You do not have access to this identity", (
        f"expected message 'You do not have access to this identity', got {lookup_message!r}"
    )

    # positive control: a valid duration on the same pool still succeeds.
    good_user = ctx.unique_name("sim2real-user-")
    resp = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: good_user}, TokenDuration=3600
    )
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[resp["IdentityId"]]))
    assert resp["Token"] and resp["IdentityId"], (
        f"expected a valid TokenDuration to vend a Token and IdentityId, got {resp!r}"
    )

    # LookupDeveloperIdentity resolves the new identity independently of the call that made it;
    # by DeveloperUserIdentifier it returns one IdentityId plus a DeveloperUserIdentifierList.
    lookup_resp = cid.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=good_user, MaxResults=10
    )
    assert lookup_resp.get("IdentityId") == resp["IdentityId"], (
        f"expected LookupDeveloperIdentity to resolve the vended identity "
        f"{resp['IdentityId']!r} for {good_user!r}, got {lookup_resp.get('IdentityId')!r}"
    )
    assert good_user in lookup_resp.get("DeveloperUserIdentifierList", []), (
        f"expected {good_user!r} in the resolved DeveloperUserIdentifierList, "
        f"got {lookup_resp.get('DeveloperUserIdentifierList')}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
