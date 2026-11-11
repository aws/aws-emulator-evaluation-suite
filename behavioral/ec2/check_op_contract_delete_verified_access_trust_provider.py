"""op-contract-deleteVerifiedAccessTrustProvider."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVerifiedAccessTrustProvider"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVerifiedAccessTrustProvider removes the provider; a second delete is rejected NotFound."""
    ec2 = ctx.client("ec2")

    created = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realvatp",
        OidcOptions={
            "Issuer": "https://sim2real.example.com/oidc",
            "AuthorizationEndpoint": "https://sim2real.example.com/oidc/authorize",
            "TokenEndpoint": "https://sim2real.example.com/oidc/token",
            "UserInfoEndpoint": "https://sim2real.example.com/oidc/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        TagSpecifications=[_tag_spec(ctx, "verified-access-trust-provider", "vatp")],
    )
    tp_id = created["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            try:
                ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVerifiedAccessTrustProviderId.NotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    # success path: the trust provider is created and describable
    described = ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[tp_id])
    described_id = described["VerifiedAccessTrustProviders"][0]["VerifiedAccessTrustProviderId"]
    assert described_id == tp_id, f"expected describe to echo the created trust provider {tp_id!r}, got {described_id!r}"

    delete_resp = ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    state["deleted"] = True
    deleted_id = delete_resp["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    assert deleted_id == tp_id, f"expected delete response to echo the deleted trust provider {tp_id!r}, got {deleted_id!r}"

    # it must be gone from describe now
    not_found = (
        "InvalidVerifiedAccessTrustProviderId.NotFound",
        f"VerifiedAccessTrustProvider {tp_id} does not exist",
    )
    gone = _error(lambda: ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[tp_id]))
    assert gone == not_found, f"unexpected error describing a deleted trust provider: {gone!r}"

    # distinct error boundary: deleting the same (already-deleted) trust provider again is rejected
    redelete = _error(lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id))
    assert redelete == not_found, f"unexpected error re-deleting a trust provider: {redelete!r}"


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
