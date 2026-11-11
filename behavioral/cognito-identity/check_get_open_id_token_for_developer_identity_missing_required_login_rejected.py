"""get-open-id-token-for-developer-identity-missing-required-login-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-missing-required-login-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity with a Logins map lacking the pool's DeveloperProviderName
    is refused with InvalidParameterException and the exact message and links nothing, while the
    correctly keyed control login resolves to its identity."""
    cip = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-provider-")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    # Positive control: Logins keyed by the pool's configured developer provider succeeds.
    identity_id = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: "sim2real-user-1"}
    )["IdentityId"]
    assert identity_id.startswith(f"{ctx.region}:"), (
        f"expected identity id region-prefixed with {ctx.region!r}, got {identity_id!r}"
    )

    # Break exactly one thing: Logins present, but keyed by a provider that is not the
    # pool's configured DeveloperProviderName.
    code, message = _refusal(
        lambda: cip.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={"some.other.provider": "sim2real-user-2"}
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a Logins map missing the pool's "
        f"configured developer provider key, got {code!r}: {message!r}"
    )
    assert message == "This identity pool does not support the specified developer provider.", (
        message
    )

    # Effect absent: the mis-keyed attempt did not partially create/link an identity
    # for "sim2real-user-2" -- a subsequent, correctly-keyed request for that same
    # user identifier mints a genuinely fresh identity, distinct from identity_id.
    resolved_user2 = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: "sim2real-user-2"}
    )["IdentityId"]
    assert resolved_user2 != identity_id, (
        "rejected mis-keyed attempt must not have linked sim2real-user-2 to the "
        f"user-1 identity, but both resolved to {resolved_user2!r}"
    )
    assert resolved_user2.startswith(f"{ctx.region}:"), (
        f"expected identity id region-prefixed with {ctx.region!r}, got {resolved_user2!r}"
    )

    # Control still works: the original correctly-keyed developer identity is still
    # resolvable to the same identity ID.
    resolved = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: "sim2real-user-1"}
    )["IdentityId"]
    assert resolved == identity_id, (
        f"expected repeat login for sim2real-user-1 to resolve back to {identity_id!r}, "
        f"got {resolved!r}"
    )


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
