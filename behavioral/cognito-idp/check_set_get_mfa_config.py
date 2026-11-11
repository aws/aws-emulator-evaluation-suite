"""set-get-mfa-config."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "set-get-mfa-config"
GROUP = 'mfa-config'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserPoolMfaConfig state is readable via GetUserPoolMfaConfig, and the pool this
    check creates is provably gone -- not just deleted, but unusable -- once it deletes it."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool_idempotent(c, _id))

    initial = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert initial.get("MfaConfiguration") == "OFF", (
        f"expected MFA OFF on a fresh pool, got {initial.get('MfaConfiguration')}"
    )

    resp = c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="ON",
    )
    assert resp.get("MfaConfiguration") == "ON", (
        f"expected MfaConfiguration ON in the response, got {resp.get('MfaConfiguration')}"
    )

    got = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert got.get("MfaConfiguration") == "ON", (
        f"expected MfaConfiguration ON after set, got {got.get('MfaConfiguration')}"
    )
    assert got.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, (
        f"expected software-token MFA enabled, got {got.get('SoftwareTokenMfaConfiguration')}"
    )

    c.delete_user_pool(UserPoolId=pool_id)
    code, message = _error(lambda: c.get_user_pool_mfa_config(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading MFA config of a deleted pool, got {code}"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_pool_idempotent(c, pool_id):
    from botocore.exceptions import ClientError

    try:
        c.delete_user_pool(UserPoolId=pool_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
