"""update-identity-provider-missing-required-oidc-detail-rejected."""
from __future__ import annotations

from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-identity-provider-missing-required-oidc-detail-rejected"
GROUP = "validation-rejects-incomplete-oidc-details"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

_DETAILS_FULL = {
    "client_id": "sim2real-behav-client-id",
    "client_secret": "sim2real-behav-client-secret",
    "attributes_request_method": "GET",
    "oidc_issuer": "https://sim2real-behav.example.com/oidc",
    "authorize_scopes": "openid",
    "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
    "token_url": "https://sim2real-behav.example.com/oidc/token",
    "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
    "jwks_uri": "https://sim2real-behav.example.com/oidc/jwks",
}


def _error(fn) -> tuple[str, str]:
    """Call fn(); return botocore (Error.Code, Error.Message). Raise if fn unexpectedly
    succeeds, so a falsy sentinel can never be mistaken for a real code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityProvider rejects ProviderDetails missing token_url with
    InvalidParameterException naming the issuer host; stored details stay untouched, and a
    complete update still succeeds."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    provider_name = ctx.unique_name("sim2realbehavoidc").replace("-", "")[:32]

    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=_DETAILS_FULL,
    )
    ctx.on_cleanup(
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )

    details_missing_token_url = {k: v for k, v in _DETAILS_FULL.items() if k != "token_url"}
    code, message = _error(
        lambda: idp.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            ProviderDetails=details_missing_token_url,
        )
    )
    # With an endpoint missing, Cognito falls back to OIDC discovery from oidc_issuer; the issuer
    # host does not resolve, and the refusal names that host.
    expected_message = urlparse(_DETAILS_FULL["oidc_issuer"]).hostname
    assert (code, message) == ("InvalidParameterException", expected_message), (
        f"expected InvalidParameterException {expected_message!r} for ProviderDetails missing "
        f"token_url, got {code!r}: {message!r}"
    )

    unchanged = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert unchanged["ProviderDetails"].get("token_url") == _DETAILS_FULL["token_url"], (
        f"a rejected update must leave ProviderDetails untouched, "
        f"got token_url={unchanged['ProviderDetails'].get('token_url')!r}"
    )

    details_v2 = dict(_DETAILS_FULL, authorize_scopes="openid profile")
    idp.update_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderDetails=details_v2,
    )
    applied = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert applied["ProviderDetails"]["authorize_scopes"] == "openid profile", (
        f"expected the positive control's complete update to apply, "
        f"got authorize_scopes={applied['ProviderDetails'].get('authorize_scopes')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
