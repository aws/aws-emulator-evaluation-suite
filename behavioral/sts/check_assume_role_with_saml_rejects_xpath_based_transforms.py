"""assume-role-with-saml-rejects-xpath-based-transforms."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-saml-rejects-xpath-based-transforms"
GROUP = "overly-permissive"
SERVICES = ["sts"]

_AWS_SIGNIN_RECIPIENT = "https://signin.aws.amazon.com/saml"

# The two XPath-family XML-DSig Transform algorithms, each used with an expression
# that is a mathematically-defined NO-OP over the signed node-set (verified below, not assumed):
#
#   - XPath 1.0 Filtering (http://www.w3.org/TR/1999/REC-xpath-19991116): the spec evaluates the
#     expression once per node with that node as context and includes the node iff the result,
#     converted to boolean, is true. "true()" is context-independent and always true, so every
#     node is included -- the output node-set is identical to the input.
#   - XPath Filter 2.0 (http://www.w3.org/2002/06/xmldsig-filter2), a "union" filter over "/":
#     union only ever ADDS nodes to what's already selected (the whole post-enveloped-signature
#     node-set), and "/" selects the document node whose implied subtree is everything -- so the
#     union changes nothing either.
#
# Because both are no-ops on the node-set, the Reference's DigestValue is byte-identical to the
# plain enveloped+exclusive-c14n case; only the declared Transforms list (and so the SignedInfo
# bytes) differs, isolating "does STS accept this Transform algorithm" from "is the digest valid".
_XPATH1_TRANSFORM = (
    '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">'
    '<ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">true()</ds:XPath>'
    "</ds:Transform>"
)
_XPATH_FILTER2_TRANSFORM = (
    '<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
    '<dsig-xpath:XPath xmlns:dsig-xpath="http://www.w3.org/2002/06/xmldsig-filter2" '
    'Filter="union">/</dsig-xpath:XPath>'
    "</ds:Transform>"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleWithSAML rejects with "Response signature invalid" an assertion whose Reference
    declares an XPath 1.0 or XPath Filter 2.0 Transform, though its digest equals the plain
    assertion's, which succeeds before and after."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    setup = _setup_saml_trust(ctx, iam)
    ctx.on_cleanup(setup["cleanup"])

    now = dt.datetime.now(dt.timezone.utc)

    def _response(extra_transform_xml: str = "") -> str:
        return _build_saml_response(
            setup["key"],
            setup["cert_der"],
            entity_id=setup["entity_id"],
            role_arn=setup["role_arn"],
            principal_arn=setup["provider_arn"],
            session_name=setup["session_name"],
            not_before=now - dt.timedelta(seconds=30),
            not_on_or_after=now + dt.timedelta(minutes=10),
            extra_transform_xml=extra_transform_xml,
        )

    # Positive control: the plain, correctly signed assertion succeeds.
    assumed = _poll_until(
        lambda: _try_assume_saml(sts, setup, _response()),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert assumed["Credentials"]["AccessKeyId"]

    for label, transform_xml in (
        ("xpath-1.0-true", _XPATH1_TRANSFORM),
        ("xpath-filter2-union-root", _XPATH_FILTER2_TRANSFORM),
    ):
        # Two assertions sharing id/timestamps must have byte-identical digests, so a rejection
        # below can only be about the Transform algorithm, never a broken digest.
        fixed_id = "_a" + uuid.uuid4().hex
        fixed_instant = _fmt_time(now)
        baseline_digest = _reference_digest(
            _response_with_fixed_id(setup, now, fixed_id, fixed_instant, "")
        )
        variant_digest = _reference_digest(
            _response_with_fixed_id(setup, now, fixed_id, fixed_instant, transform_xml)
        )
        assert variant_digest == baseline_digest, (
            f"[{label}] the no-op transform changed the Reference digest ({variant_digest!r} "
            f"!= {baseline_digest!r}); this variant is not a clean isolation of the "
            "Transform-algorithm question and must not be used as one"
        )

        variant_response = _response(extra_transform_xml=transform_xml)
        captured: dict = {}

        def _call_variant():
            captured["resp"] = sts.assume_role_with_saml(
                RoleArn=setup["role_arn"],
                PrincipalArn=setup["provider_arn"],
                SAMLAssertion=variant_response,
            )

        code, message = _error_code_stable(_call_variant)
        assert code is not None, (
            f"[{label}] AssumeRoleWithSAML ACCEPTED a digest-valid assertion whose signature "
            f"declares an XPath-family Transform: {captured.get('resp', {}).get('AssumedRoleUser')}"
        )
        assert code == "InvalidIdentityToken", (
            f"[{label}] unexpected error code for an XPath-family Transform in the signature: {code!r}"
        )
        assert message == "Response signature invalid", f"[{label}] the refusal message is {message!r}"

        again = _error_code_stable(_call_variant)
        assert again == ("InvalidIdentityToken", message), f"[{label}] retry gave {again!r}"

    restored = _poll_until(
        lambda: _try_assume_saml(sts, setup, _response()),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert restored["Credentials"]["AccessKeyId"]


def _error_code_stable(fn, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return None, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "InvalidIdentityToken" and "doesn't exist" in message and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, message


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


def _try_assume_saml(sts_client, setup, saml_response: str):
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
        if code == "InvalidIdentityToken" and "doesn't exist" in message:
            return None
        raise


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


def _assertion_xml_body(
    *,
    assertion_id: str,
    issue_instant: str,
    entity_id: str,
    role_arn: str,
    principal_arn: str,
    session_name: str,
    not_before: dt.datetime,
    not_on_or_after: dt.datetime,
    signature_xml: str = "",
) -> str:
    """Already-canonical (Exclusive-C14N) form: single xmlns declared at the root,
    alphabetically-sorted attributes, no self-closing tags, no insignificant whitespace."""
    return (
        f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{assertion_id}" IssueInstant="{issue_instant}" Version="2.0">'
        f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
        + signature_xml
        + "<saml2:Subject>"
        f'<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{session_name}</saml2:NameID>'
        '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml2:SubjectConfirmationData NotOnOrAfter="{_fmt_time(not_on_or_after)}" Recipient="{_AWS_SIGNIN_RECIPIENT}"></saml2:SubjectConfirmationData>'
        "</saml2:SubjectConfirmation>"
        "</saml2:Subject>"
        f'<saml2:Conditions NotBefore="{_fmt_time(not_before)}" NotOnOrAfter="{_fmt_time(not_on_or_after)}">'
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


def _signed_info_xml(assertion_id: str, digest_b64: str, extra_transform_xml: str = "") -> str:
    return (
        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>'
        f'<ds:Reference URI="#{assertion_id}">'
        "<ds:Transforms>"
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
        + extra_transform_xml
        + '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>'
        "</ds:Transforms>"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>'
        f"<ds:DigestValue>{digest_b64}</ds:DigestValue>"
        "</ds:Reference>"
        "</ds:SignedInfo>"
    )


def _response_with_fixed_id(setup, now, assertion_id, issue_instant, extra_transform_xml) -> str:
    """Build a response with a pinned assertion id/timestamp so two variants differing only in
    `extra_transform_xml` can be digest-compared directly."""
    return _build_saml_response(
        setup["key"],
        setup["cert_der"],
        entity_id=setup["entity_id"],
        role_arn=setup["role_arn"],
        principal_arn=setup["provider_arn"],
        session_name=setup["session_name"],
        not_before=now - dt.timedelta(seconds=30),
        not_on_or_after=now + dt.timedelta(minutes=10),
        extra_transform_xml=extra_transform_xml,
        assertion_id=assertion_id,
        issue_instant=issue_instant,
    )


def _reference_digest(saml_response_b64: str) -> str:
    """The <ds:DigestValue> of an already-built response."""
    xml = base64.b64decode(saml_response_b64).decode("utf-8")
    start = xml.index("<ds:DigestValue>") + len("<ds:DigestValue>")
    end = xml.index("</ds:DigestValue>", start)
    return xml[start:end]


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
    extra_transform_xml: str = "",
    assertion_id: str | None = None,
    issue_instant: str | None = None,
) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    assertion_id = assertion_id or ("_a" + uuid.uuid4().hex)
    response_id = "_r" + uuid.uuid4().hex
    issue_instant = issue_instant or _fmt_time(not_before)

    # The enveloped-signature transform hashes the node-set without the Signature element; the
    # extra XPath transforms are no-ops over it, so the digest does not change.
    digest_b64 = _sha256_b64(
        _assertion_xml_body(
            assertion_id=assertion_id,
            issue_instant=issue_instant,
            entity_id=entity_id,
            role_arn=role_arn,
            principal_arn=principal_arn,
            session_name=session_name,
            not_before=not_before,
            not_on_or_after=not_on_or_after,
        ).encode("utf-8")
    )

    signed_info = _signed_info_xml(assertion_id, digest_b64, extra_transform_xml=extra_transform_xml)
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
    full_assertion = _assertion_xml_body(
        assertion_id=assertion_id,
        issue_instant=issue_instant,
        entity_id=entity_id,
        role_arn=role_arn,
        principal_arn=principal_arn,
        session_name=session_name,
        not_before=not_before,
        not_on_or_after=not_on_or_after,
        signature_xml=signature_xml,
    )

    response_xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{response_id}" IssueInstant="{issue_instant}" Version="2.0" '
        f'Destination="{_AWS_SIGNIN_RECIPIENT}">'
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
        SAMLMetadataDocument=metadata_xml, Name=provider_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                    "StringEquals": {"SAML:aud": _AWS_SIGNIN_RECIPIENT}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        iam.delete_role(RoleName=role_name)
        iam.delete_saml_provider(SAMLProviderArn=provider_arn)

    return {
        "entity_id": entity_id,
        "key": key,
        "cert_der": cert_der,
        "provider_arn": provider_arn,
        "role_arn": role_arn,
        "session_name": ctx.unique_name("samluser")[:60],
        "cleanup": _cleanup,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
