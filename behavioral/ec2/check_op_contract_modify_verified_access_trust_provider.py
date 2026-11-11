"""op-contract-modify-verified-access-trust-provider."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-trust-provider"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessTrustProvider updates the description, echoed and read back; an unknown
    trust provider id fails with InvalidVerifiedAccessTrustProviderId.NotFound naming that id."""
    ec2 = ctx.client("ec2")

    vatp_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName=ctx.unique_name("sim2real_vatp_").replace("-", "_"),
        OidcOptions={
            "Issuer": "https://sim2real-behavioral-test.example.com",
            "AuthorizationEndpoint": "https://sim2real-behavioral-test.example.com/authorize",
            "TokenEndpoint": "https://sim2real-behavioral-test.example.com/token",
            "UserInfoEndpoint": "https://sim2real-behavioral-test.example.com/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        TagSpecifications=_tag_spec(
            ctx, "verified-access-trust-provider", ctx.unique_name("sim2real-vatp-")
        ),
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=vatp_id))

    new_desc = ctx.unique_name("sim2real-vatp-desc-")
    resp = ec2.modify_verified_access_trust_provider(
        VerifiedAccessTrustProviderId=vatp_id, Description=new_desc
    )
    assert resp["VerifiedAccessTrustProvider"]["Description"] == new_desc, resp["VerifiedAccessTrustProvider"]

    described = ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[vatp_id])[
        "VerifiedAccessTrustProviders"
    ][0]
    assert described["Description"] == new_desc, "modification did not persist"

    code, message = _client_error(
        lambda: ec2.modify_verified_access_trust_provider(
            VerifiedAccessTrustProviderId="vatp-00000000000000000", Description="x"
        )
    )
    assert code == "InvalidVerifiedAccessTrustProviderId.NotFound", f"unexpected error code: {code}"
    # Only the stable end of the not-found message is pinned.
    assert message.endswith(" vatp-00000000000000000 does not exist"), (
        f"expected the not-found message for vatp-00000000000000000, got {message!r}"
    )


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
