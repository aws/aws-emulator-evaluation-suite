"""get-signing-certificate-returns-valid-cert."""
from __future__ import annotations

import base64
import binascii

from behavioral_harness import tags

CHECK = "get-signing-certificate-returns-valid-cert"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSigningCertificate returns server-managed certificate material, not caller-supplied."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-signcert-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    resp1 = cognito.get_signing_certificate(UserPoolId=pool_id)
    cert1 = resp1["Certificate"]
    assert cert1, "GetSigningCertificate returned an empty certificate"
    assert len(cert1) > 100, f"certificate looks too short to be real: {cert1!r}"

    try:
        decoded = base64.b64decode(cert1, validate=True)
    except (binascii.Error, ValueError) as e:
        raise AssertionError(f"Certificate is not valid base64: {e}") from e
    assert len(decoded) > 100, f"decoded certificate body is too short to be a real X.509 cert: {len(decoded)} bytes"
    # A real X.509 certificate is DER-encoded ASN.1: an outer SEQUENCE, tag byte 0x30.
    # This is what distinguishes an actual certificate from an arbitrary base64 blob of
    # the same length.
    assert decoded[0] == 0x30, f"expected a DER-encoded X.509 certificate (ASN.1 SEQUENCE tag 0x30), got first byte {decoded[0]:#x}"

    # The signing certificate is server-managed: repeated reads return identical material
    # rather than something derived per-request or caller-influenced.
    resp2 = cognito.get_signing_certificate(UserPoolId=pool_id)
    assert resp2["Certificate"] == cert1, "signing certificate was not stable across reads"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
