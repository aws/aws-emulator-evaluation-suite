"""saml-provider-lifecycle."""
from __future__ import annotations

import datetime as _dt
import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "saml-provider-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SAML provider create->active->metadata-updated->deleted->absent-from-list transitions."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-saml-")

    cert = _self_signed_cert_pem(ctx, common_name="sim2real-behav-saml.example.com")
    metadata_v1 = _saml_metadata("https://sim2real-behav.example.com/entity/v1", cert["cert_body_b64"])

    created = iam.create_saml_provider(
        SAMLMetadataDocument=metadata_v1, Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = created["SAMLProviderArn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_saml_provider(SAMLProviderArn=arn)))

    got = iam.get_saml_provider(SAMLProviderArn=arn)
    assert got["CreateDate"] is not None, f"GetSAMLProvider for {arn} must report a CreateDate"
    assert "https://sim2real-behav.example.com/entity/v1" in got["SAMLMetadataDocument"], (
        f"GetSAMLProvider for {arn} must return the uploaded v1 metadata, got {got['SAMLMetadataDocument'][:200]!r}"
    )

    providers = {p["Arn"] for p in iam.list_saml_providers()["SAMLProviderList"]}
    assert arn in providers, f"newly created {arn} must appear in ListSAMLProviders, got {providers}"

    metadata_v2 = _saml_metadata("https://sim2real-behav.example.com/entity/v2", cert["cert_body_b64"])
    iam.update_saml_provider(SAMLProviderArn=arn, SAMLMetadataDocument=metadata_v2)

    got = iam.get_saml_provider(SAMLProviderArn=arn)
    assert "https://sim2real-behav.example.com/entity/v2" in got["SAMLMetadataDocument"], (
        f"GetSAMLProvider for {arn} must return the updated v2 metadata, got {got['SAMLMetadataDocument'][:200]!r}"
    )
    assert "https://sim2real-behav.example.com/entity/v1" not in got["SAMLMetadataDocument"], (
        f"GetSAMLProvider for {arn} must not still return the superseded v1 metadata"
    )

    iam.delete_saml_provider(SAMLProviderArn=arn)

    providers_after = {p["Arn"] for p in iam.list_saml_providers()["SAMLProviderList"]}
    assert arn not in providers_after, f"deleted provider {arn} must not appear in ListSAMLProviders, got {providers_after}"

    get_code, get_message = _error(lambda: iam.get_saml_provider(SAMLProviderArn=arn))
    assert get_code == "NoSuchEntity", f"GetSAMLProvider on deleted {arn} must fail NoSuchEntity, got {get_code}"
    want_get = f"Manifest not found for arn {arn}"
    assert get_message == want_get, f"GetSAMLProvider message: expected {want_get!r}, got {get_message!r}"

    update_code, update_message = _error(
        lambda: iam.update_saml_provider(SAMLProviderArn=arn, SAMLMetadataDocument=metadata_v2)
    )
    assert update_code == "NoSuchEntity", (
        f"UpdateSAMLProvider on deleted {arn} must fail NoSuchEntity (mutation on a dead id), got {update_code}"
    )
    want_update = f"Manifest not found for arn {arn}"
    assert update_message == want_update, (
        f"UpdateSAMLProvider message: expected {want_update!r}, got {update_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _self_signed_cert_pem(ctx, common_name: str) -> dict:
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
        raise AssertionError(f"unreachable: openssl failed to generate a test certificate: {proc.stderr[:300]}")
    combined = proc.stdout
    cert_start = combined.index("-----BEGIN CERTIFICATE-----")
    cert_end = combined.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    cert_pem = combined[cert_start:cert_end].strip() + "\n"
    body_lines = [
        line for line in cert_pem.splitlines()
        if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    ]
    return {"cert_pem": cert_pem, "cert_body_b64": "".join(body_lines)}


def _saml_metadata(entity_id: str, cert_body_b64: str) -> str:
    valid_until = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    padding = "x" * 200  # ensure we comfortably clear IAM's 1000-char metadata minimum
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}" validUntil="{valid_until}">\n'
        '  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
        'WantAuthnRequestsSigned="false">\n'
        '    <KeyDescriptor use="signing">\n'
        '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
        '        <ds:X509Data>\n'
        f'          <ds:X509Certificate>{cert_body_b64}</ds:X509Certificate>\n'
        '        </ds:X509Data>\n'
        '      </ds:KeyInfo>\n'
        '    </KeyDescriptor>\n'
        '    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        'Location="https://idp.sim2real-behav.example.com/sso/redirect"/>\n'
        '    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        'Location="https://idp.sim2real-behav.example.com/sso/post"/>\n'
        '  </IDPSSODescriptor>\n'
        '</EntityDescriptor>\n'
        f'<!-- padding-{padding} -->\n'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
