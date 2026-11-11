"""op-contract-get-user-pool-mfa-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-user-pool-mfa-config"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserPoolMfaConfig reflects the pool's MFA setting (default OFF on a new pool);
    a bogus UserPoolId 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    cfg = idp.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert cfg["MfaConfiguration"] == "OFF", cfg["MfaConfiguration"]

    idp.set_user_pool_mfa_config(UserPoolId=pool_id, MfaConfiguration="OPTIONAL", SoftwareTokenMfaConfiguration={"Enabled": True})
    cfg2 = idp.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert cfg2["MfaConfiguration"] == "OPTIONAL", cfg2["MfaConfiguration"]
    assert cfg2.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, cfg2.get(
        "SoftwareTokenMfaConfiguration"
    )

    bogus_id = pool_id[:-4] + "zzzz"
    err = _client_error(lambda: idp.get_user_pool_mfa_config(UserPoolId=bogus_id))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = f"User pool {bogus_id} does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
