"""op-contract-create-verified-access-group."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-verified-access-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVerifiedAccessGroup: success creates a group bound to its instance with the
    supplied policy document; DryRun=True is honored (permission-checked, no mutation)."""
    ec2 = ctx.client("ec2")
    instance_id = _create_instance(ctx)
    _attach_trust_provider(ctx, instance_id)
    policy_doc = (
        'permit(principal, action, resource) when { context.http_request.method == "GET" };'
    )

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(
        lambda: ec2.create_verified_access_group(VerifiedAccessInstanceId=instance_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got: {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    before = ec2.describe_verified_access_groups(VerifiedAccessInstanceId=instance_id)[
        "VerifiedAccessGroups"
    ]
    assert before == [], f"DryRun must not create a group, but found: {before!r}"

    # --- success path ---
    name = ctx.unique_name("sim2real-behav-vag-")
    resp = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=instance_id,
        PolicyDocument=policy_doc,
        TagSpecifications=[{"ResourceType": "verified-access-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    group = resp["VerifiedAccessGroup"]
    group_id = group["VerifiedAccessGroupId"]
    ctx.on_cleanup(lambda: _delete_group(ctx, group_id))
    assert group["VerifiedAccessInstanceId"] == instance_id, (
        f"expected group bound to {instance_id!r}, got {group['VerifiedAccessInstanceId']!r}"
    )
    assert "VerifiedAccessGroupArn" in group, f"expected an ARN in the create response, got {group!r}"

    fetched = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)
    assert fetched["PolicyEnabled"] is True, f"expected PolicyEnabled=True, got {fetched!r}"
    assert fetched["PolicyDocument"] == policy_doc, (
        f"expected policy document {policy_doc!r}, got {fetched['PolicyDocument']!r}"
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


def _create_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vai-")
    instance_id = ec2.create_verified_access_instance(
        Description=name,
        TagSpecifications=[{"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))
    return instance_id


def _attach_trust_provider(ctx, instance_id: str) -> str:
    # AWS requires a trust provider to be attached to a Verified Access instance
    # before any group can be created against it (even for a DryRun call).
    ec2 = ctx.client("ec2")
    policy_reference_name = ctx.unique_name("sim2realbehav").replace("-", "")[:32]
    tag_name = ctx.unique_name("sim2real-behav-vatp-")
    oidc_options = {
        "Issuer": "https://issuer.example.com",
        "AuthorizationEndpoint": "https://issuer.example.com/authorize",
        "TokenEndpoint": "https://issuer.example.com/token",
        "UserInfoEndpoint": "https://issuer.example.com/userinfo",
        "ClientId": "sim2real-client-id",
        "ClientSecret": "sim2real-client-secret",
        "Scope": "openid",
    }
    tp_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName=policy_reference_name,
        OidcOptions=oidc_options,
        TagSpecifications=[
            {"ResourceType": "verified-access-trust-provider", "Tags": [{"Key": "Name", "Value": tag_name}]}
        ],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(lambda: _detach_and_delete_trust_provider(ctx, instance_id, tp_id))
    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=tp_id
    )
    return tp_id


def _detach_and_delete_trust_provider(ctx, instance_id: str, tp_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_verified_access_trust_provider(
            VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=tp_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessInstanceId.NotFound":
            raise
    try:
        ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessTrustProviderId.NotFound":
            raise


def _delete_group(ctx, group_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessGroupId.NotFound":
            raise


def _delete_instance(ctx, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessInstanceId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
