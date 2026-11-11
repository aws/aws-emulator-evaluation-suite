"""webauthn-config-accepted-without-essentials-tier."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "webauthn-config-accepted-without-essentials-tier"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserPoolMfaConfig with a WebAuthnConfiguration is accepted on a LITE pool, and
    GetUserPoolMfaConfig returns its RelyingPartyId localhost."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTier="LITE", UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    # SetUserPoolMfaConfig must accept a WebAuthn config on a LITE-tier pool (the tier gate is
    # not enforced); a refusal raises its ClientError and fails the check with AWS's own error.
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": "localhost", "UserVerification": "preferred"},
    )

    # The accepted config is stored and round-trips.
    got = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    webauthn = got.get("WebAuthnConfiguration") or {}
    assert webauthn.get("RelyingPartyId") == "localhost", got.get("WebAuthnConfiguration")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
