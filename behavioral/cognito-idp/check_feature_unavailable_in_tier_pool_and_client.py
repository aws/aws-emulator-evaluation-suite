"""feature-unavailable-in-tier-pool-and-client."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-unavailable-in-tier-pool-and-client"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _retry_throttled(fn, *, max_attempts: int = 8, base_delay: float = 1.0):
    """Retry fn() with exponential backoff on TooManyRequestsException. Any
    other ClientError propagates.
    Applied to cleanup deletes too: ctx.run_cleanups() swallows a callback's
    exception so one throttled delete never blocks the rest, but that same
    swallowing means a throttled delete leaks its resource invisibly --
    nothing in the run's report shows it."""
    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


def _error(fn):
    """Call fn() (throttle-retried); return its botocore (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting a call real AWS refuses is never read as a code mismatch."""
    try:
        result = _retry_throttled(fn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdvancedSecurityMode ENFORCED on an ESSENTIALS pool fails with FeatureUnavailableInTierException
    in CreateUserPool and UpdateUserPool but succeeds on PLUS; on the ESSENTIALS pool
    EnablePropagateAdditionalUserContextData needs a client secret; each refusal has its exact message."""
    c = ctx.client("cognito-idp")

    # CreateUserPool: explicitly pin ESSENTIALS while asking for a Plus-only add-on.
    code1 = _error(
        lambda: c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
            UserPoolTier="ESSENTIALS",
            UserPoolAddOns={"AdvancedSecurityMode": "ENFORCED"},
        )
    )
    assert code1 == ("FeatureUnavailableInTierException", "The following features need to be disabled for the ESSENTIALS pricing tier configured: Threat Protection"), (
        f"CreateUserPool: expected FeatureUnavailableInTierException, got {code1}"
    )

    # UpdateUserPool: pool created at the (default) Essentials tier, then asked
    # for the same Plus-only add-on without ever upgrading the tier.
    pool_id = _retry_throttled(
        lambda: c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
        )
    )["UserPool"]["Id"]
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: c.delete_user_pool(UserPoolId=pool_id), max_attempts=4, base_delay=0.5
        )
    )
    desc = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc.get("UserPoolTier", "ESSENTIALS") == "ESSENTIALS", desc.get("UserPoolTier")

    code2 = _error(
        lambda: c.update_user_pool(
            UserPoolId=pool_id, UserPoolAddOns={"AdvancedSecurityMode": "ENFORCED"}
        )
    )
    assert code2 == ("FeatureUnavailableInTierException", "The following features need to be disabled for the ESSENTIALS pricing tier configured: Threat Protection"), (
        f"UpdateUserPool: expected FeatureUnavailableInTierException, got {code2}"
    )
    desc_after = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc_after.get("UserPoolAddOns", {}).get("AdvancedSecurityMode", "INACTIVE") in (
        "INACTIVE",
        None,
    ), "a rejected UpdateUserPool must not have applied the Plus-only add-on"

    # CreateUserPoolClient: a client with no secret cannot set the field --
    # this is on the SAME Essentials-tier, add-on-inactive pool_id used above,
    # so nothing about the pool's tier changed between this and its restore.
    code3 = _error(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            GenerateSecret=False,
            EnablePropagateAdditionalUserContextData=True,
        )
    )
    assert code3 == ("InvalidParameterException", "Client Secret is required to set EnablePropagateAdditionalUserContextData as true"), (
        f"CreateUserPoolClient: expected InvalidParameterException, got {code3}"
    )

    # RESTORE (CreateUserPoolClient half) + positive control: GenerateSecret is
    # create-time-only and cannot be added later via UpdateUserPoolClient, so
    # the restore for code3 is a fresh create with the ONE input corrected --
    # still on this SAME low-tier pool. Succeeding here (not
    # FeatureUnavailableInTierException, not any rejection) is what shows the
    # boundary above is the secret, not the pool's tier/add-on state.
    secret_client_id = _retry_throttled(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            GenerateSecret=True,
            EnablePropagateAdditionalUserContextData=True,
        )
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=secret_client_id),
            max_attempts=4,
            base_delay=0.5,
        )
    )
    secret_client_desc = c.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=secret_client_id
    )["UserPoolClient"]
    assert secret_client_desc.get("EnablePropagateAdditionalUserContextData") is True, (
        f"CreateUserPoolClient with a secret must succeed on this SAME low-tier pool and "
        f"persist the field, got {secret_client_desc.get('EnablePropagateAdditionalUserContextData')}"
    )

    # UpdateUserPoolClient: same field via update, on a client that has no
    # secret -- the secret requirement applies at update time too.
    secretless_client_id = _retry_throttled(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-")
        )
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=secretless_client_id),
            max_attempts=4,
            base_delay=0.5,
        )
    )
    code4 = _error(
        lambda: c.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=secretless_client_id,
            EnablePropagateAdditionalUserContextData=True,
        )
    )
    assert code4 == ("InvalidParameterException", "Client Secret is required to set EnablePropagateAdditionalUserContextData as true"), (
        f"UpdateUserPoolClient: expected InvalidParameterException, got {code4}"
    )

    # RESTORE (UpdateUserPoolClient half): the identical update call, on a
    # client that DOES have a secret (created without the field, so this is
    # the update -- not the create -- that turns it on), must succeed. Still
    # this SAME low-tier pool.
    secret_only_client_id = _retry_throttled(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            GenerateSecret=True,
        )
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=secret_only_client_id),
            max_attempts=4,
            base_delay=0.5,
        )
    )
    _retry_throttled(
        lambda: c.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=secret_only_client_id,
            EnablePropagateAdditionalUserContextData=True,
        )
    )
    secret_only_desc = c.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=secret_only_client_id
    )["UserPoolClient"]
    assert secret_only_desc.get("EnablePropagateAdditionalUserContextData") is True, (
        f"UpdateUserPoolClient with a secret must succeed on this SAME low-tier pool and "
        f"persist the field, got {secret_only_desc.get('EnablePropagateAdditionalUserContextData')}"
    )

    # RESTORE (UpdateUserPool half): upgrade the SAME pool to Plus and turn the
    # add-on ENFORCED -- the identical call from code2 must now succeed. This
    # also doubles as the positive control for code2/code3/code4: it proves the
    # target can activate this add-on at all, not merely reject every request.
    _retry_throttled(
        lambda: c.update_user_pool(
            UserPoolId=pool_id,
            UserPoolTier="PLUS",
            UserPoolAddOns={"AdvancedSecurityMode": "ENFORCED"},
        )
    )
    desc_restored = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc_restored.get("UserPoolTier") == "PLUS", desc_restored.get("UserPoolTier")
    assert desc_restored.get("UserPoolAddOns", {}).get("AdvancedSecurityMode") == "ENFORCED", (
        f"upgrading tier and add-on together must activate ENFORCED, "
        f"got {desc_restored.get('UserPoolAddOns')}"
    )

    # RESTORE (CreateUserPool half): the identical create call from code1, with
    # Plus pinned instead of Essentials, must succeed outright.
    restored_pool_id = _retry_throttled(
        lambda: c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
            UserPoolTags=_TAGS,
            UserPoolTier="PLUS",
            UserPoolAddOns={"AdvancedSecurityMode": "ENFORCED"},
        )
    )["UserPool"]["Id"]
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: c.delete_user_pool(UserPoolId=restored_pool_id), max_attempts=4, base_delay=0.5
        )
    )
    restored_pool_desc = c.describe_user_pool(UserPoolId=restored_pool_id)["UserPool"]
    assert restored_pool_desc.get("UserPoolTier") == "PLUS", restored_pool_desc.get("UserPoolTier")
    assert restored_pool_desc.get("UserPoolAddOns", {}).get("AdvancedSecurityMode") == "ENFORCED", (
        f"CreateUserPool with Plus pinned must activate ENFORCED outright, "
        f"got {restored_pool_desc.get('UserPoolAddOns')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
