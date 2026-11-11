"""op-contract-get-verified-access-group-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-verified-access-group-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVerifiedAccessGroupPolicy: default-disabled policy for a fresh group, NotFound for a bogus id."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-va-group-policy-")

    trust_provider_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realidp",
        OidcOptions={
            "Issuer": "https://sim2real.example.com/oidc",
            "AuthorizationEndpoint": "https://sim2real.example.com/oidc/authorize",
            "TokenEndpoint": "https://sim2real.example.com/oidc/token",
            "UserInfoEndpoint": "https://sim2real.example.com/oidc/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        TagSpecifications=[
            {"ResourceType": "verified-access-trust-provider", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(
        lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=trust_provider_id)
    )

    instance_id = ec2.create_verified_access_instance(
        Description=ctx.unique_name("sim2real-va-instance-"),
        TagSpecifications=[
            {"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id))

    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
    )

    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id,
        TagSpecifications=[
            {"ResourceType": "verified-access-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))

    resp = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)
    assert "PolicyEnabled" in resp
    assert resp["PolicyEnabled"] is False, "a freshly created group should have no enabled policy"
    assert not resp.get("PolicyDocument"), "a freshly created group should have no policy document"

    code = _error_code(
        lambda: ec2.get_verified_access_group_policy(VerifiedAccessGroupId="vagr-0000000000000000")
    )
    assert "notfound" in code.lower(), f"unexpected error code {code!r}"
    assert "verifiedaccess" in code.lower(), (
        f"expected a Verified-Access-specific NotFound code, got {code!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"expected a ClientError for a nonexistent verified access group id, but the call "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
