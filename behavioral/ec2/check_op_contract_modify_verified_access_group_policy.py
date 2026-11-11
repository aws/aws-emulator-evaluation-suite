"""op-contract-modify-verified-access-group-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-group-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessGroupPolicy sets a Cedar policy on the group; bad group id -> NotFound."""
    ec2 = ctx.client("ec2")

    vai_id = ec2.create_verified_access_instance(
        TagSpecifications=[_tag_spec(ctx, "verified-access-instance", "vagp-inst")]
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
        TagSpecifications=[_tag_spec(ctx, "verified-access-trust-provider", "vagp-tp")],
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
        TagSpecifications=[_tag_spec(ctx, "verified-access-group", "vagp-group")],
    )["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))

    policy_doc = "permit(principal, action, resource);"
    resp = ec2.modify_verified_access_group_policy(
        VerifiedAccessGroupId=group_id, PolicyEnabled=True, PolicyDocument=policy_doc
    )
    assert resp["PolicyEnabled"] is True, resp
    assert resp["PolicyDocument"].strip() == policy_doc, resp["PolicyDocument"]

    described = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)
    assert described["PolicyEnabled"] is True, described
    assert described["PolicyDocument"].strip() == policy_doc, (
        f"expected the modified policy document to persist, got {described['PolicyDocument']!r}"
    )

    code, code_msg = _client_error(
        lambda: ec2.modify_verified_access_group_policy(
            VerifiedAccessGroupId="vagr-00000000000000000", PolicyEnabled=True, PolicyDocument=policy_doc
        )
    )
    assert code == "InvalidVerifiedAccessGroupId.NotFound", f"unexpected error code: {code}"
    assert code_msg == "The verified-access-group ID 'vagr-00000000000000000' does not exist", code_msg


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
