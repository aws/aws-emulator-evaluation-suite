"""assume-role-with-saml-non-base64-assertion-rejected."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import time
import uuid

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-saml-non-base64-assertion-rejected"
GROUP = 'assume-role-with-saml'
SERVICES = ['sts']

_NON_BASE64_MESSAGE = (
    "Invalid base64 SAMLResponse (Service: AWSOpenIdDiscoveryService; Status Code: 400; "
    "Error Code: AuthSamlInvalidSamlResponseException; Request ID: <request-id>; Proxy: null)"
)
# The message embeds a per-call request id; it is the only part that varies.
_REQUEST_ID = re.compile(r"Request ID: [0-9a-fA-F-]{36}")


def _stable(message: str) -> str:
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


def _error_code_and_message(fn):
    """The (code, message) of the refusal ``fn`` raises; raises AssertionError when ``fn`` succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected a refusal, but the call succeeded: {resp.get('AssumedRoleUser')!r}"
    )


def _anonymous_client(ctx, service: str = "sts"):
    """Client that sends UNSIGNED requests -- for the STS operations that are genuinely
    unauthenticated (AssumeRoleWithWebIdentity / WithSAML)."""
    return ctx.client(
        service,
        config=Config(signature_version=UNSIGNED, retries={"max_attempts": 1}),
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SAMLAssertion that is not valid base64 is rejected as InvalidIdentityToken naming
    AuthSamlInvalidSamlResponseException, not the "no such provider" error, against a real
    provider whose correctly signed assertion succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    setup = _setup_saml_trust(ctx, iam)
    ctx.on_cleanup(setup["cleanup"])

    now = dt.datetime.now(dt.timezone.utc)

    # Positive control: proves AssumeRoleWithSAML is not simply rejecting every call.
    valid_response = _build_saml_response(
        setup["key"],
        setup["cert_der"],
        entity_id=setup["entity_id"],
        role_arn=setup["role_arn"],
        principal_arn=setup["provider_arn"],
        session_name=setup["session_name"],
        not_before=now - dt.timedelta(seconds=30),
        not_on_or_after=now + dt.timedelta(minutes=10),
    )
    assumed = _poll_until(
        lambda: _try_assume_saml(sts, setup, valid_response),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert assumed["Credentials"]["AccessKeyId"], "positive control did not yield credentials"

    client = _anonymous_client(ctx, "sts")
    code, msg = _error_code_and_message(
        lambda: client.assume_role_with_saml(
            RoleArn=setup["role_arn"],
            PrincipalArn=setup["provider_arn"],
            SAMLAssertion="!!!not-base64-at-all!!!",
        )
    )
    assert (code, _stable(msg)) == ("InvalidIdentityToken", _NON_BASE64_MESSAGE), (
        f"got {code!r}: {msg!r}"
    )

    # A retry must fail the same way, never be sometimes accepted.
    code_again, msg_again = _error_code_and_message(
        lambda: client.assume_role_with_saml(
            RoleArn=setup["role_arn"],
            PrincipalArn=setup["provider_arn"],
            SAMLAssertion="!!!not-base64-at-all!!!",
        )
    )
    assert (code_again, _stable(msg_again)) == ("InvalidIdentityToken", _NON_BASE64_MESSAGE), (
        f"got {code_again!r}: {msg_again!r}"
    )


# ===== SAML assertion construction =====
#
# The assertion is hand-built in Exclusive-C14N canonical form and its XML-DSig Signature is
# computed over those bytes with `cryptography` (RSA-PKCS1v15/SHA-256): canonicalizing an
# already-canonical document is the identity transform, so AWS's re-canonicalization on receipt
# reproduces the signed bytes.


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
        'Location="https://sim2real-test-idp.example.com/sso"/>'
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
    status_value: str = "Success",
    audience_uri: str = "https://signin.aws.amazon.com/saml",
) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    assertion_id = "_a" + uuid.uuid4().hex
    response_id = "_r" + uuid.uuid4().hex
    issue_instant = _fmt_time(not_before)

    def _assertion_xml(signature_xml: str = "") -> str:
        """Already-canonical (Exclusive-C14N) form: single xmlns declared at
        the root, alphabetically-sorted attributes, no self-closing tags, no
        insignificant whitespace between elements."""
        return (
            f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="{assertion_id}" IssueInstant="{issue_instant}" Version="2.0">'
            f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
            + signature_xml
            + "<saml2:Subject>"
            f'<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{session_name}</saml2:NameID>'
            '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml2:SubjectConfirmationData NotOnOrAfter="{_fmt_time(not_on_or_after)}" Recipient="https://signin.aws.amazon.com/saml"></saml2:SubjectConfirmationData>'
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

    # The enveloped-signature transform hashes the node-set without the Signature element.
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
        'Destination="https://signin.aws.amazon.com/saml">'
        f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
        "<samlp:Status>"
        f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{status_value}"></samlp:StatusCode>'
        "</samlp:Status>"
        f"{full_assertion}"
        "</samlp:Response>"
    )
    return base64.b64encode(response_xml.encode()).decode()


def _setup_saml_trust(ctx, iam) -> dict:
    entity_id = f"https://{ctx.unique_name('sim2real-saml-idp-')}.example.com/"
    key, cert_der = _make_idp_keypair_and_cert("sim2real-saml-test-idp")
    cert_der_b64 = _b64(cert_der)
    metadata_xml = _saml_metadata_xml(entity_id, cert_der_b64)

    provider_name = ctx.unique_name("sim2real-samlp-")
    provider_arn = iam.create_saml_provider(
        SAMLMetadataDocument=metadata_xml, Name=provider_name
    )["SAMLProviderArn"]

    role_name = ctx.unique_name("sim2real-samlrole-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]

    def _cleanup():
        # NoSuchEntity means the resource is already gone; anything else is a real failure.
        try:
            iam.delete_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            pass
        try:
            iam.delete_saml_provider(SAMLProviderArn=provider_arn)
        except iam.exceptions.NoSuchEntityException:
            pass

    return {
        "entity_id": entity_id,
        "key": key,
        "cert_der": cert_der,
        "provider_arn": provider_arn,
        "role_arn": role_arn,
        "session_name": ctx.unique_name("samluser")[:60],
        "cleanup": _cleanup,
    }


_SAML_PROVIDER_PROPAGATION_SUBCODES = (
    "AuthSamlManifestNotFoundException",  # "Specified provider doesn't exist"
    "AuthSamlIDPNotFoundException",  # "Unable to fetch Issuer Data"
)


def _try_assume_saml(sts_client, setup, saml_response: str):
    """AssumeRoleWithSAML, retrying only the two InvalidIdentityToken sub-codes a just-created
    provider returns while still invisible to STS; any other error raises."""
    try:
        return sts_client.assume_role_with_saml(
            RoleArn=setup["role_arn"],
            PrincipalArn=setup["provider_arn"],
            SAMLAssertion=saml_response,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        if code == "AccessDenied":
            return None
        if code == "InvalidIdentityToken" and any(
            sub in message for sub in _SAML_PROVIDER_PROPAGATION_SUBCODES
        ):
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
