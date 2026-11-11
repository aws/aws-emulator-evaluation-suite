"""update-identity-pool-developer-provider-name-immutable-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-identity-pool-developer-provider-name-immutable-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityPool with a different DeveloperProviderName succeeds but keeps the original
    name, both in its response and in a fresh DescribeIdentityPool."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real_pool_").replace("-", "_")
    dev_provider = "login.sim2real.original"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real-check": "update-identity-pool-developer-provider-name-immutable-rejected"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    before = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert before["DeveloperProviderName"] == dev_provider, (
        f"expected the pool to be created with DeveloperProviderName={dev_provider!r}, "
        f"got {before.get('DeveloperProviderName')!r}"
    )

    error_code = None
    update_resp = None
    try:
        update_resp = ci.update_identity_pool(
            IdentityPoolId=pool_id,
            IdentityPoolName=name,
            AllowUnauthenticatedIdentities=True,
            DeveloperProviderName="login.sim2real.changed",
        )
    except ClientError as err:
        error_code = err.response["Error"]["Code"]

    if update_resp is not None:
        # The call was not rejected outright; the change to the immutable field must still not
        # have been applied, and the response must not lie about it either.
        assert update_resp.get("DeveloperProviderName") == dev_provider, (
            "UpdateIdentityPool response must not report the rejected DeveloperProviderName "
            f"change, got {update_resp.get('DeveloperProviderName')!r}"
        )

    after = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert after["DeveloperProviderName"] == dev_provider, (
        "DeveloperProviderName must remain unchanged "
        f"(update error_code={error_code!r}), got {after.get('DeveloperProviderName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
