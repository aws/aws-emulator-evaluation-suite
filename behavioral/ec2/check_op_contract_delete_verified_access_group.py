"""op-contract-deleteVerifiedAccessGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVerifiedAccessGroup"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVerifiedAccessGroup removes the group; describing/re-deleting it afterwards fails NotFound."""
    ec2 = ctx.client("ec2")

    instance = ec2.create_verified_access_instance(
        TagSpecifications=[_tag_spec(ctx, "verified-access-instance", "vaig-inst")]
    )
    instance_id = instance["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)))

    # a verified-access instance must have a trust provider attached before a group can be created
    trust_provider_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realvagtp",
        OidcOptions={
            "Issuer": "https://sim2real.example.com/oidc",
            "AuthorizationEndpoint": "https://sim2real.example.com/oidc/authorize",
            "TokenEndpoint": "https://sim2real.example.com/oidc/token",
            "UserInfoEndpoint": "https://sim2real.example.com/oidc/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        TagSpecifications=[_tag_spec(ctx, "verified-access-trust-provider", "vag-tp")],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=trust_provider_id))
    )
    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.detach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=trust_provider_id
            )
        )
    )

    created = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id,
        TagSpecifications=[_tag_spec(ctx, "verified-access-group", "vag")],
    )
    group_id = created["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))

    ctx.on_cleanup(_cleanup)

    described = ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[group_id])
    assert described["VerifiedAccessGroups"][0]["VerifiedAccessGroupId"] == group_id, described
    assert described["VerifiedAccessGroups"][0]["VerifiedAccessInstanceId"] == instance_id, described

    delete_resp = ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    state["deleted"] = True
    assert delete_resp["VerifiedAccessGroup"]["VerifiedAccessGroupId"] == group_id, delete_resp

    # distinct error boundary: re-deleting the already-deleted group is rejected
    code, message = _error(lambda: ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id))
    assert code == "InvalidVerifiedAccessGroupId.NotFound", f"unexpected error re-deleting a group: {code}: {message}"
    assert message == f"The verified-access-group ID '{group_id}' does not exist", message

    # terminal assertion is an independent read at the destination, issued through a
    # different operation than either delete: the group must genuinely be gone
    code, message = _error(lambda: ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[group_id]))
    assert code == "InvalidVerifiedAccessGroupId.NotFound", f"unexpected error describing a deleted group: {code}: {message}"
    assert message == f"VerifiedAccessGroup {group_id} does not exist", message


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


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidVerifiedAccessGroupId.NotFound",
            "InvalidVerifiedAccessInstanceId.NotFound",
            "InvalidVerifiedAccessTrustProviderId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
