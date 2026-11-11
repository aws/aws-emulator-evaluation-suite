"""op-contract-get-signing-certificate."""
from __future__ import annotations

import base64
import binascii

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-signing-certificate"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSigningCertificate returns a real X.509 certificate (base64-encoded DER, not
    PEM) used to verify SAML responses for the pool, and rejects a syntactically valid
    but nonexistent pool id."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # success path: a real certificate is returned for an existing pool. Cognito returns
    # the certificate as base64-encoded DER (no "-----BEGIN CERTIFICATE-----" PEM
    # wrapper), so decode it and confirm it structurally looks like an X.509
    # certificate: DER-encoded ASN.1 SEQUENCE, i.e. it starts with tag byte 0x30.
    cert = idp.get_signing_certificate(UserPoolId=pool_id)["Certificate"]
    try:
        der = base64.b64decode(cert, validate=True)
    except (binascii.Error, ValueError) as e:
        raise AssertionError(f"expected base64-encoded certificate data, got {cert!r}") from e
    assert len(der) > 100, f"expected a substantial DER certificate body, got {len(der)} bytes"
    assert der[0] == 0x30, (
        f"expected a DER-encoded X.509 certificate (ASN.1 SEQUENCE tag 0x30), got tag byte {der[0]:#x}"
    )

    # distinct error boundary: a syntactically valid but nonexistent pool id is rejected
    fake_id = f"{ctx.region}_ZZZZZZZZZ"
    code, message = _error(lambda: idp.get_signing_certificate(UserPoolId=fake_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"User pool {fake_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
