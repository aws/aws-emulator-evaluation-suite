"""op-contract-modify-verified-access-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessGroup updates the Description; bad group id -> NotFound."""
    ec2 = ctx.client("ec2")

    vai_id = ec2.create_verified_access_instance(
        TagSpecifications=[_tag_spec(ctx, "verified-access-instance", "vaig-inst")]
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=vai_id))

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
        TagSpecifications=[_tag_spec(ctx, "verified-access-trust-provider", "vaig-tp")],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=vatp_id))
    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=vai_id, VerifiedAccessTrustProviderId=vatp_id
    )
    ctx.on_cleanup(
        lambda: ec2.detach_verified_access_trust_provider(
            VerifiedAccessInstanceId=vai_id, VerifiedAccessTrustProviderId=vatp_id
        )
    )

    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=vai_id,
        Description="initial",
        TagSpecifications=[_tag_spec(ctx, "verified-access-group", "vaig-group")],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))

    new_desc = ctx.unique_name("sim2real-vag-desc-")
    resp = ec2.modify_verified_access_group(VerifiedAccessGroupId=group_id, Description=new_desc)
    assert resp["VerifiedAccessGroup"]["Description"] == new_desc, resp["VerifiedAccessGroup"]

    described = ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[group_id])["VerifiedAccessGroups"][0]
    assert described["Description"] == new_desc, "modification did not persist"

    code, message = _client_error(
        lambda: ec2.modify_verified_access_group(VerifiedAccessGroupId="vagr-00000000000000000", Description="x")
    )
    assert code == "InvalidVerifiedAccessGroupId.NotFound", f"unexpected error code: {code}"
    expected_message = "The verified-access-group ID 'vagr-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
