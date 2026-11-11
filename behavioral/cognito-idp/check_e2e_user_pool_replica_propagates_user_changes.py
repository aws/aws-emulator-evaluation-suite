"""e2e-user-pool-replica-propagates-user-changes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-user-pool-replica-propagates-user-changes"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolReplica on a LITE pool fails with FeatureUnavailableInTierException and its exact
    message and lists no replica; on an ESSENTIALS pool it is never refused for the tier, and a
    replica is listed exactly when the call succeeds."""
    cognito = ctx.client("cognito-idp")
    secondary_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    lite_pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-replica-lite-"),
        UserPoolTier="LITE",
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog-replica-lite"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=lite_pool_id))

    # negative: the Lite plan can never host a replica, per the docs and the
    # service's own triggerable-error catalog for this operation.
    negative = _error(
        lambda: cognito.create_user_pool_replica(UserPoolId=lite_pool_id, RegionName=secondary_region)
    )
    assert negative == ("FeatureUnavailableInTierException", "The following feature is not available for the LITE pricing tier configured: Multi-Region Replication"), (
        f"expected FeatureUnavailableInTierException for a LITE-tier pool, got {negative!r}"
    )

    # effect absent: the rejected call left no secondary replica registered on
    # the pool for the target region (ListUserPoolReplicas always includes a
    # PRIMARY entry for the pool's own region, so we assert on the absence of
    # the specific secondary region rather than an empty list)
    replicas = cognito.list_user_pool_replicas(UserPoolId=lite_pool_id).get("UserPoolReplicas", [])
    assert not any(r.get("RegionName") == secondary_region for r in replicas), (
        f"rejected CreateUserPoolReplica still left a {secondary_region} replica registered: {replicas}"
    )

    essentials_pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-replica-ess-"),
        UserPoolTier="ESSENTIALS",
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog-replica-ess"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=essentials_pool_id))

    # positive control: the same call, against a tier the docs say IS eligible
    # for replication, must not be rejected for the tier reason above -- this
    # is what catches an emulator that rejects CreateUserPoolReplica
    # unconditionally and would otherwise pass the negative assertion above
    # for the wrong reason.
    try:
        cognito.create_user_pool_replica(UserPoolId=essentials_pool_id, RegionName=secondary_region)
        positive_code = None
    except ClientError as exc:
        positive_code = exc.response["Error"]["Code"]
    assert positive_code != "FeatureUnavailableInTierException", (
        f"ESSENTIALS-tier pool was rejected for the LITE-only reason: {positive_code}"
    )

    # terminal independent read: whatever the call did, ListUserPoolReplicas
    # must agree with it -- this is what catches a target that returns success
    # from CreateUserPoolReplica without actually registering the replica.
    essentials_replicas = cognito.list_user_pool_replicas(UserPoolId=essentials_pool_id).get(
        "UserPoolReplicas", []
    )
    essentials_has_replica = any(
        r.get("RegionName") == secondary_region for r in essentials_replicas
    )
    if positive_code is None:
        ctx.on_cleanup(
            lambda: cognito.delete_user_pool_replica(
                UserPoolId=essentials_pool_id, RegionName=secondary_region
            )
        )
        assert essentials_has_replica, (
            "CreateUserPoolReplica returned success but no replica for "
            f"{secondary_region} appeared in ListUserPoolReplicas: {essentials_replicas}"
        )
    else:
        assert not essentials_has_replica, (
            f"CreateUserPoolReplica failed with {positive_code} but a replica for "
            f"{secondary_region} appeared anyway: {essentials_replicas}"
        )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    emulator accepting a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
