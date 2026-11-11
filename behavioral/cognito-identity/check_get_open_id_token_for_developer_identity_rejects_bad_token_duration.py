"""get-open-id-token-for-developer-identity-rejects-bad-token-duration."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-rejects-bad-token-duration"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity with TokenDuration above 86400 is refused with
    ValidationException and the exact constraint message, LookupDeveloperIdentity for that user
    answers NotAuthorizedException, and a valid call on the pool succeeds."""
    ev = ctx.client("cognito-identity")
    dev_provider = "login.myapp"
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName=dev_provider)

    bad_user = ctx.unique_name("sim2real-behav-devuser-")
    bad_duration = 999999999
    code, message = _refusal(
        lambda: ev.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            Logins={dev_provider: bad_user},
            TokenDuration=bad_duration,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for out-of-range TokenDuration, got {code!r}: {message!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{bad_duration}' at 'tokenDuration' failed to satisfy "
        "constraint: Member must have value less than or equal to 86400"
    ), message

    # effect absent: the rejected call never registered bad_user as a developer identity.
    lookup_code, lookup_message = _refusal(
        lambda: ev.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=bad_user, MaxResults=10
        )
    )
    assert lookup_code == "NotAuthorizedException", (
        f"expected the rejected TokenDuration call to leave no identity behind, "
        f"got {lookup_code!r}: {lookup_message!r}"
    )
    assert lookup_message == "You do not have access to this identity", lookup_message

    # positive control: a valid duration on the same pool still succeeds.
    good_user = ctx.unique_name("sim2real-behav-devuser-")
    resp = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: good_user}, TokenDuration=3600
    )
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=[resp["IdentityId"]]))
    assert resp.get("Token") and resp.get("IdentityId"), (
        f"positive control did not vend a token/identity: {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
