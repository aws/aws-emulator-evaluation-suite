"""get-signing-certificate-stable-across-repeated-calls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-signing-certificate-stable-across-repeated-calls"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSigningCertificate returns the byte-identical certificate on repeated calls: absent a
    rotation, the pool's signing certificate is stable, not minted per call."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    cert1 = cognito.get_signing_certificate(UserPoolId=pool_id)["Certificate"]
    cert2 = cognito.get_signing_certificate(UserPoolId=pool_id)["Certificate"]
    cert3 = cognito.get_signing_certificate(UserPoolId=pool_id)["Certificate"]

    assert isinstance(cert1, str) and len(cert1) > 50, f"unexpectedly short certificate: {cert1!r}"
    assert cert1 == cert2 == cert3, "GetSigningCertificate returned different values across repeated calls"


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
