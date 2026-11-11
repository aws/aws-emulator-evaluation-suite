"""lookup-developer-identity-empty-result-no-error."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lookup-developer-identity-empty-result-no-error"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LookupDeveloperIdentity for an identity with no developer login is refused with
    NotAuthorizedException "You do not have access to this identity", while on the same pool a
    linked identity resolves to its developer user identifier."""
    client = ctx.client("cognito-identity")
    dev_provider = f"login.{ctx.unique_name('sim2real')}"
    pool_id = _create_pool(ctx, client, DeveloperProviderName=dev_provider)

    # an identity that has never been linked via a developer provider
    unlinked_identity_id = client.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # MaxResults is documented as optional, but real AWS validates it against QueryLimit's
    # range (>= 1) even when omitted, rejecting an implied 0 with a ValidationException — so an
    # explicit value >= 1 is required on every call, not just paginated ones.
    try:
        resp = client.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=unlinked_identity_id, MaxResults=1
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "NotAuthorizedException", (
            f"expected NotAuthorizedException looking up an identity with no linked developer "
            f"login, got {code}"
        )
        expected = "You do not have access to this identity"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"expected NotAuthorizedException looking up an identity with no linked developer "
            f"login, call succeeded with {resp}"
        )

    # Positive control, same pool: an identity that DOES have an active developer login
    # resolves normally -- proving the rejection above is "no link", not a blanket failure of
    # LookupDeveloperIdentity on this pool.
    dev_user_id = ctx.unique_name("sim2real-devuser-")
    linked_identity_id = client.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_id}
    )["IdentityId"]
    linked = client.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=linked_identity_id, MaxResults=1
    )
    assert linked["IdentityId"] == linked_identity_id, linked
    assert dev_user_id in linked.get("DeveloperUserIdentifierList", []), (
        f"expected {dev_user_id} in DeveloperUserIdentifierList for the linked identity, "
        f"got {linked}"
    )


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
