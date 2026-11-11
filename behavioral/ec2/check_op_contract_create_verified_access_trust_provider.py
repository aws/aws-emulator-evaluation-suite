"""op-contract-create-verified-access-trust-provider."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-verified-access-trust-provider"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVerifiedAccessTrustProvider: success creates a user/oidc trust provider with
    the supplied policy reference name; DryRun=True is honored (permission-checked, no
    mutation)."""
    ec2 = ctx.client("ec2")
    policy_reference_name = ctx.unique_name("sim2realbehav").replace("-", "")[:32]
    oidc_options = {
        "Issuer": "https://issuer.example.com",
        "AuthorizationEndpoint": "https://issuer.example.com/authorize",
        "TokenEndpoint": "https://issuer.example.com/token",
        "UserInfoEndpoint": "https://issuer.example.com/userinfo",
        "ClientId": "sim2real-client-id",
        "ClientSecret": "sim2real-client-secret",
        "Scope": "openid",
    }

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(
        lambda: ec2.create_verified_access_trust_provider(
            TrustProviderType="user",
            UserTrustProviderType="oidc",
            PolicyReferenceName=policy_reference_name,
            OidcOptions=oidc_options,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    before = ec2.describe_verified_access_trust_providers(
        Filters=[{"Name": "policy-reference-name", "Values": [policy_reference_name]}]
    )["VerifiedAccessTrustProviders"]
    assert before == [], "DryRun must not create a trust provider"

    # --- success path ---
    resp = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName=policy_reference_name,
        OidcOptions=oidc_options,
        TagSpecifications=[
            {
                "ResourceType": "verified-access-trust-provider",
                "Tags": [{"Key": "Name", "Value": policy_reference_name}],
            }
        ],
    )
    tp = resp["VerifiedAccessTrustProvider"]
    tp_id = tp["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: _delete_trust_provider(ctx, tp_id))
    assert tp["TrustProviderType"] == "user", f"expected user, got {tp['TrustProviderType']!r}"
    assert tp["UserTrustProviderType"] == "oidc", f"expected oidc, got {tp['UserTrustProviderType']!r}"
    assert tp["PolicyReferenceName"] == policy_reference_name, (
        f"expected {policy_reference_name!r}, got {tp['PolicyReferenceName']!r}"
    )
    assert tp["OidcOptions"]["Issuer"] == oidc_options["Issuer"], (
        f"expected {oidc_options['Issuer']!r}, got {tp['OidcOptions']['Issuer']!r}"
    )
    # the client secret must never be echoed back in the clear: real AWS returns the literal
    # sentinel "REDACTED", not the submitted value and not an absent field
    assert tp["OidcOptions"]["ClientSecret"] == "REDACTED", tp["OidcOptions"]

    fetched = ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[tp_id])[
        "VerifiedAccessTrustProviders"
    ]
    assert len(fetched) == 1, f"expected exactly 1 trust provider for {tp_id}, got {fetched!r}"
    assert fetched[0]["PolicyReferenceName"] == policy_reference_name, (
        f"expected {policy_reference_name!r}, got {fetched[0]['PolicyReferenceName']!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_trust_provider(ctx, tp_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessTrustProviderId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
