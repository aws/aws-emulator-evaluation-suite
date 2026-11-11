"""assume-role-with-saml-expired-assertion-rejected."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-saml-expired-assertion-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]
EXPIRED_MESSAGE = "Token must be redeemed within 5 minutes of issuance"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """AssumeRoleWithSAML rejects a validly signed assertion whose NotOnOrAfter has passed with
    ExpiredTokenException, on every retry, while an otherwise-identical currently-valid
    assertion succeeds before and after and yields usable credentials."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    key, cert_der = _make_idp_keypair_and_cert(ctx.unique_name("sim2real-saml-idp-"))
    entity_id = f"https://{ctx.unique_name('sim2real-saml-idp-')}.example.com/"
    metadata_xml = _saml_metadata_xml(entity_id, base64.b64encode(cert_der).decode())

    check_tag = [{"Key": "sim2real-check", "Value": CHECK}]

    provider_name = ctx.unique_name("sim2real-behav-samlidp2-")
    provider_arn = iam.create_saml_provider(
        Name=provider_name, SAMLMetadataDocument=metadata_xml, Tags=check_tag
    )["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=provider_arn))

    role_name = ctx.unique_name("sim2real-behav-samlrole2-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=check_tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("samluser")[:60]

    def _assume(not_before: dt.datetime, not_on_or_after: dt.datetime) -> dict:
        assertion = _build_saml_response(
            key,
            cert_der,
            entity_id=entity_id,
            role_arn=role_arn,
            principal_arn=provider_arn,
            session_name=session_name,
            not_before=not_before,
            not_on_or_after=not_on_or_after,
        )
        return sts.assume_role_with_saml(
            RoleArn=role_arn, PrincipalArn=provider_arn, SAMLAssertion=assertion
        )

    def _assume_or_none(not_before: dt.datetime, not_on_or_after: dt.datetime):
        try:
            return _assume(not_before, not_on_or_after)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            # A new SAML provider or trust policy takes seconds to propagate; STS surfaces this
            # as AccessDenied or as InvalidIdentityToken saying the provider doesn't exist.
            if code == "AccessDenied":
                return None
            if code == "InvalidIdentityToken" and "doesn't exist" in message:
                return None
            raise

    def _assume_error(not_before: dt.datetime, not_on_or_after: dt.datetime) -> tuple[str, str]:
        """``(code, message)`` of the refusal; raises if the assertion is accepted."""
        try:
            _assume(not_before, not_on_or_after)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(
            "AssumeRoleWithSAML accepted an assertion whose validity window has passed"
        )

    def _fresh_valid_window() -> tuple[dt.datetime, dt.datetime]:
        live = dt.datetime.now(dt.timezone.utc)
        return live - dt.timedelta(seconds=30), live + dt.timedelta(minutes=10)

    # Positive control: a valid assertion succeeds and the minted session itself is usable.
    valid_before, valid_after = _fresh_valid_window()
    assumed = _poll_until(
        lambda: _assume_or_none(valid_before, valid_after),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    as_role = _client_for_credentials(ctx, assumed["Credentials"], "sts")
    whoami = as_role.get_caller_identity()
    assert whoami["Arn"].endswith(f"assumed-role/{role_name}/{session_name}"), whoami["Arn"]

    # The validity window is entirely in the past.
    expired_before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    expired_after = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    code, message = _assume_error(expired_before, expired_after)
    assert code == "ExpiredTokenException", f"got {code!r}"
    assert message == EXPIRED_MESSAGE, message

    code_again, message_again = _assume_error(expired_before, expired_after)
    assert code_again == "ExpiredTokenException", f"got {code_again!r}"
    assert message_again == EXPIRED_MESSAGE, message_again

    # A valid assertion still succeeds: the rejection was specific to the expired window.
    valid_before, valid_after = _fresh_valid_window()
    restored = _poll_until(
        lambda: _assume_or_none(valid_before, valid_after),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert restored["Credentials"]["AccessKeyId"]


# The SAML assertion is hand-built already in Exclusive-C14N canonical form and signed directly
# with `cryptography` (RSA-PKCS1v15/SHA-256): canonicalizing an already-canonical document is the
# identity transform, so AWS's re-canonicalization on receipt reproduces the signed bytes.


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


def _client_for_credentials(ctx, creds: dict, service: str):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _fmt_time(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _sha256_b64(data: bytes) -> str:
    return _b64(hashlib.sha256(data).digest())


def _make_idp_keypair_and_cert(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return key, cert_der


def _saml_metadata_xml(entity_id: str, cert_der_b64: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        '<IDPSSODescriptor WantAuthnRequestsSigned="false" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing">'
        '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f"<ds:X509Data><ds:X509Certificate>{cert_der_b64}</ds:X509Certificate></ds:X509Data>"
        "</ds:KeyInfo></KeyDescriptor>"
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        'Location="https://sim2real-behav.example.com/sso"/>'
        "</IDPSSODescriptor></EntityDescriptor>"
    )


def _build_saml_response(
    key,
    cert_der: bytes,
    *,
    entity_id: str,
    role_arn: str,
    principal_arn: str,
    session_name: str,
    not_before: dt.datetime,
    not_on_or_after: dt.datetime,
    audience_uri: str = "https://signin.aws.amazon.com/saml",
) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    assertion_id = "_a" + uuid.uuid4().hex
    response_id = "_r" + uuid.uuid4().hex
    issue_instant = _fmt_time(not_before)

    def _assertion_xml(signature_xml: str = "") -> str:
        return (
            f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="{assertion_id}" IssueInstant="{issue_instant}" Version="2.0">'
            f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
            + signature_xml
            + "<saml2:Subject>"
            f'<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{session_name}</saml2:NameID>'
            '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml2:SubjectConfirmationData NotOnOrAfter="{_fmt_time(not_on_or_after)}" Recipient="{audience_uri}"></saml2:SubjectConfirmationData>'
            "</saml2:SubjectConfirmation>"
            "</saml2:Subject>"
            f'<saml2:Conditions NotBefore="{_fmt_time(not_before)}" NotOnOrAfter="{_fmt_time(not_on_or_after)}">'
            f"<saml2:AudienceRestriction><saml2:Audience>{audience_uri}</saml2:Audience></saml2:AudienceRestriction>"
            "</saml2:Conditions>"
            f'<saml2:AuthnStatement AuthnInstant="{issue_instant}">'
            "<saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>"
            "</saml2:AuthnStatement>"
            "<saml2:AttributeStatement>"
            '<saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">'
            f"<saml2:AttributeValue>{role_arn},{principal_arn}</saml2:AttributeValue>"
            "</saml2:Attribute>"
            '<saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">'
            f"<saml2:AttributeValue>{session_name}</saml2:AttributeValue>"
            "</saml2:Attribute>"
            "</saml2:AttributeStatement>"
            "</saml2:Assertion>"
        )

    # Enveloped-signature transform: the digest covers the assertion without its Signature.
    digest_b64 = _sha256_b64(_assertion_xml(signature_xml="").encode("utf-8"))

    signed_info = (
        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>'
        f'<ds:Reference URI="#{assertion_id}">'
        "<ds:Transforms>"
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>'
        "</ds:Transforms>"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>'
        f"<ds:DigestValue>{digest_b64}</ds:DigestValue>"
        "</ds:Reference>"
        "</ds:SignedInfo>"
    )
    signature_bytes = key.sign(signed_info.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = _b64(signature_bytes)

    cert_der_b64 = _b64(cert_der)
    signature_xml = (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        + signed_info
        + f"<ds:SignatureValue>{sig_b64}</ds:SignatureValue>"
        + "<ds:KeyInfo><ds:X509Data>"
        + f"<ds:X509Certificate>{cert_der_b64}</ds:X509Certificate>"
        + "</ds:X509Data></ds:KeyInfo>"
        + "</ds:Signature>"
    )

    full_assertion = _assertion_xml(signature_xml=signature_xml)

    response_xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{response_id}" IssueInstant="{issue_instant}" Version="2.0" '
        f'Destination="{audience_uri}">'
        f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
        "<samlp:Status>"
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>'
        "</samlp:Status>"
        f"{full_assertion}"
        "</samlp:Response>"
    )
    return base64.b64encode(response_xml.encode()).decode()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
