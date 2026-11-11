"""op-contract-set-user-pool-mfa-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-set-user-pool-mfa-config"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserPoolMfaConfig persists a valid OPTIONAL+software-token config, and rejects
    turning MFA fully ON with no authentication factor configured -- a rejection that is
    lifted the instant a factor is configured (the missing factor is the whole reason)."""
    cognito = ctx.client("cognito-idp")
    tags_kw = {"UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}}

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-mfacfg-"), **tags_kw
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    resp = cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    assert resp["MfaConfiguration"] == "OPTIONAL", resp
    assert resp["SoftwareTokenMfaConfiguration"]["Enabled"] is True, resp

    described = cognito.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert described["MfaConfiguration"] == "OPTIONAL", described
    assert described["SoftwareTokenMfaConfiguration"]["Enabled"] is True, described

    # Error boundary: a *fresh* pool with no MFA factor configured rejects MfaConfiguration=ON
    # (positive control above already proved the account/credentials are otherwise healthy for
    # this call). This is a state precondition, not an invalid input value: the call is refused,
    # the pool is left unchanged, and configuring a factor lets the identical call succeed.
    fresh_pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-mfacfg-fresh-"), **tags_kw
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=fresh_pool_id))

    code, message = _error(
        lambda: cognito.set_user_pool_mfa_config(UserPoolId=fresh_pool_id, MfaConfiguration="ON")
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException enabling ON with no MFA factor, got {code}"
    )
    expected = (
        "Invalid MFA Configuration given. SMS MFA, Email MFA, or Software Token MFA must be enabled."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = cognito.get_user_pool_mfa_config(UserPoolId=fresh_pool_id)
    assert unaffected.get("MfaConfiguration", "OFF") == "OFF", (
        f"rejected ON must leave the pool's MFA configuration untouched, got {unaffected}"
    )

    # Restore: configuring the missing factor is exactly what lifts the rejection.
    restored = cognito.set_user_pool_mfa_config(
        UserPoolId=fresh_pool_id,
        MfaConfiguration="ON",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    assert restored["MfaConfiguration"] == "ON", restored

    reread = cognito.get_user_pool_mfa_config(UserPoolId=fresh_pool_id)
    assert reread["MfaConfiguration"] == "ON", (
        f"expected ON to stick once a factor is configured, got {reread}"
    )
    assert reread.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, reread


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
