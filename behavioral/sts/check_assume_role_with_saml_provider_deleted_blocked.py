"""assume-role-with-saml-provider-deleted-blocked."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "assume-role-with-saml-provider-deleted-blocked"
GROUP = "overly-permissive"
SERVICES = ["sts"]

_AWS_SIGNIN_RECIPIENT = "https://signin.aws.amazon.com/saml"
_DELETED_PROVIDER_MESSAGE = (
    "Specified provider doesn't exist (Service: AWSOpenIdDiscoveryService; Status Code: 400; "
    "Error Code: AuthSamlManifestNotFoundException; Request ID: <request-id>; Proxy: null)"
)
# The message embeds a per-call request id; it is the only part that varies.
_REQUEST_ID = re.compile(r"Request ID: [0-9a-fA-F-]{36}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A correctly signed SAML assertion accepted while its IAM SAML provider exists is rejected
    with InvalidIdentityToken once that provider is deleted.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]

    # AWS validates the signature against the certificate in the uploaded metadata, so a
    # self-signed keypair acts as the IdP with no network call.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-sts-saml-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=10))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")
    entity_id = f"https://sim2real-test.invalid/idp/{ctx.unique_name('saml')}"

    metadata_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing">'
        '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f"<ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>"
        "</ds:KeyInfo></KeyDescriptor>"
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{entity_id}/sso"/>'
        "</IDPSSODescriptor></EntityDescriptor>"
    )

    provider_name = ctx.unique_name("sim2real-samlprov-")
    provider_arn = iam.create_saml_provider(
        SAMLMetadataDocument=metadata_xml,
        Name=provider_name,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["SAMLProviderArn"]
    ctx.on_cleanup(lambda: _delete_saml_provider(iam, provider_arn))

    role_name = ctx.unique_name("sim2real-samlrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {"StringEquals": {"SAML:aud": _AWS_SIGNIN_RECIPIENT}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    session_name = ctx.unique_name("samluser")[:60]
    assertion_b64 = _build_saml_response(
        key,
        cert_der,
        entity_id=entity_id,
        role_arn=role_arn,
        principal_arn=provider_arn,
        session_name=session_name,
        # AWS also enforces a 5-minute "redeem within" freshness window on
        # IssueInstant itself, independent of Conditions/NotOnOrAfter below --
        # keep this close to "now" or the positive control expires before the
        # first AssumeRoleWithSAML attempt.
        not_before=now - timedelta(seconds=30),
        not_on_or_after=now + timedelta(minutes=10),
    )

    # Positive control; IAM trust-policy propagation can lag a few seconds, so poll.
    resp, last_error = _poll_until_saml_accepted(
        sts, role_arn, provider_arn, assertion_b64, timeout_s=30.0
    )
    if resp is None:
        raise AssertionError(
            "could not obtain a successful AssumeRoleWithSAML with a freshly "
            "signed self-contained assertion against real AWS in this "
            "environment (assertion construction was rejected even with the "
            f"provider present); last error from real AWS: {last_error}; this "
            "exercises assertion-building fidelity, not the provider-deleted "
            "boundary, so it is failed rather than asserted incorrectly"
        )
    assert "Credentials" in resp and resp["Credentials"]["AccessKeyId"], (
        f"expected temporary credentials in the positive-control response, got {resp!r}"
    )
    assert f":assumed-role/{role_name}/" in resp["AssumedRoleUser"]["Arn"], (
        f"expected AssumedRoleUser.Arn to reference role {role_name!r}, "
        f"got {resp['AssumedRoleUser']['Arn']!r}"
    )

    iam.delete_saml_provider(SAMLProviderArn=provider_arn)

    # The provider itself is gone, not merely unusable for this one call.
    try:
        iam.get_saml_provider(SAMLProviderArn=provider_arn)
        raise AssertionError(
            "expected NoSuchEntity from GetSAMLProvider after DeleteSAMLProvider, "
            "but the provider is still readable"
        )
    except iam.exceptions.NoSuchEntityException:
        pass

    # A just-deleted provider can still be honoured for a moment, so poll until
    # the refusal appears and fail loudly if it never does.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            sts.assume_role_with_saml(
                RoleArn=role_arn, PrincipalArn=provider_arn, SAMLAssertion=assertion_b64
            )
        except Exception as exc:  # noqa: BLE001 - botocore ClientError
            err = getattr(exc, "response", {}).get("Error", {})
            code, message = err.get("Code"), err.get("Message", "")
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                "expected AssumeRoleWithSAML to fail after provider deletion, but it still succeeds"
            )
        time.sleep(1.0)
    # A deleted provider is caught while resolving the Federated principal, as
    # InvalidIdentityToken / "Specified provider doesn't exist", not a generic AccessDenied.
    stable = _REQUEST_ID.sub("Request ID: <request-id>", message)
    assert (code, stable) == ("InvalidIdentityToken", _DELETED_PROVIDER_MESSAGE), (
        f"expected the specific 'provider doesn't exist' rejection, got {code!r} ({message!r})"
    )


def _delete_saml_provider(iam, arn: str) -> None:
    try:
        iam.delete_saml_provider(SAMLProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, name: str) -> None:
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


# The assertion is hand-built in Exclusive-C14N canonical form and its XML-DSig Signature is
# computed over those bytes with `cryptography` (RSA-PKCS1v15/SHA-256): canonicalizing an
# already-canonical document is the identity transform, so AWS's re-canonicalization on receipt
# reproduces the signed bytes.
# AWS expects the Audience "https://signin.aws.amazon.com/saml", and <ds:Signature> must be the
# Assertion's second child (right after <Issuer>); a signature appended last is rejected as an
# invalid SAMLResponse.


def _build_saml_response(
    key,
    cert_der: bytes,
    *,
    entity_id: str,
    role_arn: str,
    principal_arn: str,
    session_name: str,
    not_before: datetime,
    not_on_or_after: datetime,
) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    assertion_id = "_a" + uuid.uuid4().hex
    response_id = "_r" + uuid.uuid4().hex
    issue_instant = not_before.strftime(fmt)

    def _assertion_xml(signature_xml: str = "") -> str:
        return (
            f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="{assertion_id}" IssueInstant="{issue_instant}" Version="2.0">'
            f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
            + signature_xml
            + "<saml2:Subject>"
            f'<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{session_name}</saml2:NameID>'
            '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml2:SubjectConfirmationData NotOnOrAfter="{not_on_or_after.strftime(fmt)}" Recipient="{_AWS_SIGNIN_RECIPIENT}"></saml2:SubjectConfirmationData>'
            "</saml2:SubjectConfirmation>"
            "</saml2:Subject>"
            f'<saml2:Conditions NotBefore="{not_before.strftime(fmt)}" NotOnOrAfter="{not_on_or_after.strftime(fmt)}">'
            f"<saml2:AudienceRestriction><saml2:Audience>{_AWS_SIGNIN_RECIPIENT}</saml2:Audience></saml2:AudienceRestriction>"
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

    # The enveloped-signature transform hashes the node-set without the Signature element.
    digest_b64 = base64.b64encode(
        hashlib.sha256(_assertion_xml(signature_xml="").encode("utf-8")).digest()
    ).decode()

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
    sig_b64 = base64.b64encode(signature_bytes).decode()

    cert_der_b64 = base64.b64encode(cert_der).decode()
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
        f'Destination="{_AWS_SIGNIN_RECIPIENT}">'
        f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
        "<samlp:Status>"
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>'
        "</samlp:Status>"
        f"{full_assertion}"
        "</samlp:Response>"
    )
    return base64.b64encode(response_xml.encode()).decode()


def _poll_until_saml_accepted(
    sts, role_arn: str, provider_arn: str, assertion_b64: str, timeout_s: float
) -> tuple[dict[str, Any] | None, str | None]:
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return (
                sts.assume_role_with_saml(
                    RoleArn=role_arn, PrincipalArn=provider_arn, SAMLAssertion=assertion_b64
                ),
                None,
            )
        except Exception as exc:  # noqa: BLE001
            last_error = repr(exc)
            time.sleep(1.5)
    return None, last_error


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
