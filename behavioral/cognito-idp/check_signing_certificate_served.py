"""signing-certificate-served."""
from __future__ import annotations

import ssl

from behavioral_harness import tags

CHECK = "signing-certificate-served"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSigningCertificate returns a valid X.509 cert for the pool's server-managed signing key."""
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-signcert-")
    pool_id = idp.create_user_pool(
        PoolName=pool_name,
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    resp = idp.get_signing_certificate(UserPoolId=pool_id)
    pem = resp["Certificate"]
    assert isinstance(pem, str) and len(pem) > 0, f"expected a non-empty certificate string, got {pem!r}"

    pem_wrapped = "-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----\n"
    der = ssl.PEM_cert_to_DER_cert(pem_wrapped)
    # A DER-encoded X.509 certificate is an ASN.1 SEQUENCE (tag 0x30).
    assert der[0] == 0x30, f"expected DER tag 0x30 (ASN.1 SEQUENCE), got {der[0]:#x}"
    assert len(der) > 100, f"expected a substantial DER certificate body, got {len(der)} bytes"

    # A second call returns the same signing certificate: it is a stable, server-managed key.
    resp2 = idp.get_signing_certificate(UserPoolId=pool_id)
    assert resp2["Certificate"] == pem, "GetSigningCertificate returned a different certificate on a second call"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
