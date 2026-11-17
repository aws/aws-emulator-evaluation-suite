"""saml-provider-assertion-encryption-required-without-a-key-rejected."""
from __future__ import annotations

import datetime as _dt
import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "saml-provider-assertion-encryption-required-without-a-key-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Requiring encrypted SAML assertions with no decryption key on file is rejected; adding
    one in the same call to set AssertionEncryptionMode to Required succeeds and is reflected
    on an independent GetSAMLProvider."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-samlenc-")

    signing_cert_b64 = _self_signed_cert_body_b64(common_name="sim2real-behav-samlenc.example.com")
    metadata = _saml_metadata("https://sim2real-behav.example.com/entity/samlenc", signing_cert_b64)

    created = iam.create_saml_provider(SAMLMetadataDocument=metadata, Name=name)
    arn = created["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=arn))

    got = iam.get_saml_provider(SAMLProviderArn=arn)
    assert got.get("PrivateKeyList", []) == [], (
        f"a freshly created provider must carry no decryption keys, got {got.get('PrivateKeyList')!r}"
    )

    code, message = _error(
        lambda: iam.update_saml_provider(SAMLProviderArn=arn, AssertionEncryptionMode="Required")
    )
    assert code == "InvalidInput", (
        f"expected InvalidInput requiring encryption with no decryption key on file, got {code!r}"
    )
    expected_message = "Failed to set assertion encryption mode to Required because no private key is present."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    got = iam.get_saml_provider(SAMLProviderArn=arn)
    assert got.get("AssertionEncryptionMode", "Allowed") == "Allowed", (
        f"the rejected call must not have changed AssertionEncryptionMode, got {got.get('AssertionEncryptionMode')!r}"
    )

    decrypt_key_pem = _rsa_private_key_pem()
    iam.update_saml_provider(
        SAMLProviderArn=arn, AssertionEncryptionMode="Required", AddPrivateKey=decrypt_key_pem
    )

    got = iam.get_saml_provider(SAMLProviderArn=arn)
    assert got["AssertionEncryptionMode"] == "Required", (
        f"expected AssertionEncryptionMode Required once a decryption key is on file, got {got.get('AssertionEncryptionMode')!r}"
    )
    key_ids = [k["KeyId"] for k in got.get("PrivateKeyList", [])]
    assert len(key_ids) == 1, f"expected exactly one decryption key on file, got {key_ids!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _self_signed_cert_body_b64(common_name: str) -> str:
    require_tools("openssl")
    proc = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", f"/CN={common_name}",
            "-keyout", "/dev/stdout", "-out", "/dev/stdout",
        ],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0 or "BEGIN CERTIFICATE" not in proc.stdout:
        raise AssertionError(f"unreachable: openssl failed to generate the signing certificate: {proc.stderr[:300]}")
    combined = proc.stdout
    cert_start = combined.index("-----BEGIN CERTIFICATE-----")
    cert_end = combined.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    cert_pem = combined[cert_start:cert_end]
    return "".join(
        line for line in cert_pem.splitlines() if line and "CERTIFICATE" not in line
    )


def _rsa_private_key_pem() -> str:
    require_tools("openssl")
    proc = subprocess.run(
        ["openssl", "genrsa", "2048"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0 or "BEGIN" not in proc.stdout:
        raise AssertionError(f"unreachable: openssl failed to generate a decryption key: {proc.stderr[:300]}")
    return proc.stdout


def _saml_metadata(entity_id: str, cert_body_b64: str) -> str:
    valid_until = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    filler = "f" * 200  # clears IAM's 1000-byte metadata-document floor
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}" validUntil="{valid_until}">\n'
        '  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        '    <KeyDescriptor use="signing">\n'
        '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
        '        <ds:X509Data>\n'
        f'          <ds:X509Certificate>{cert_body_b64}</ds:X509Certificate>\n'
        '        </ds:X509Data>\n'
        '      </ds:KeyInfo>\n'
        '    </KeyDescriptor>\n'
        '    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        'Location="https://idp.sim2real-behav.example.com/sso/redirect"/>\n'
        '  </IDPSSODescriptor>\n'
        '</EntityDescriptor>\n'
        f'<!-- filler-{filler} -->\n'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
