"""get-open-id-token-for-developer-identity-token-duration-out-of-range-rejected."""

from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-token-duration-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TokenDuration above the 86400 s maximum is refused with ValidationException and the exact
    constraint message, leaves no developer identity that LookupDeveloperIdentity finds, and a valid
    call on the same pool succeeds."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    bad_user = ctx.unique_name("user-")
    bad_duration = 86401  # max is 86400
    code, message = _refusal(
        lambda: ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            Logins={dev_provider: bad_user},
            TokenDuration=bad_duration,
        )
    )
    # Real AWS validates TokenDuration bounds as a generic request-shape violation
    # (ValidationException), not the service-specific InvalidParameterException.
    assert code == "ValidationException", f"got {code!r}: {message!r}"
    assert message == (
        f"1 validation error detected: Value '{bad_duration}' at 'tokenDuration' failed to satisfy "
        "constraint: Member must have value less than or equal to 86400"
    ), message

    # effect absent: the rejected call never registered bad_user as a developer identity.
    lookup_code, lookup_message = _refusal(
        lambda: ci.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=bad_user, MaxResults=10
        )
    )
    assert lookup_code == "NotAuthorizedException", (
        f"expected the rejected TokenDuration call to leave no identity behind, "
        f"got {lookup_code!r}: {lookup_message!r}"
    )
    assert lookup_message == "You do not have access to this identity", lookup_message

    # positive control: a valid duration on the same pool still succeeds.
    good_user = ctx.unique_name("user-")
    resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: good_user}, TokenDuration=3600
    )
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[resp["IdentityId"]]))
    assert resp["Token"] and resp["IdentityId"], (
        f"expected an in-range TokenDuration to still succeed on the same pool, got {resp!r}"
    )


def _refusal(fn: Any) -> tuple[str, str]:
    """Call fn(); return the refusal's (Code, Message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
