"""e2e-saml-provider-role-trust-federation-flow."""
from __future__ import annotations

import base64
import datetime
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-saml-provider-role-trust-federation-flow"
GROUP = "e2e"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a SAML provider referenced in a role's trust policy leaves the trust document
    unchanged while the provider becomes unreachable: IAM runs no cascading integrity check on
    trust policies."""
    iam = ctx.client("iam")
    provider_name = ctx.unique_name("sim2real-behav-saml-")
    role_name = ctx.unique_name("sim2real-behav-role-")
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    metadata_document = _self_signed_saml_metadata(provider_name)
    provider_arn = iam.create_saml_provider(
        SAMLMetadataDocument=metadata_document,
        Name=provider_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SAMLProviderArn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_saml_provider(SAMLProviderArn=provider_arn)))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert any(p["PolicyArn"] == policy_arn for p in attached), (
        f"expected {policy_arn} attached to {role_name}, got {attached!r}"
    )

    before_delete = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert before_delete["Statement"][0]["Principal"]["Federated"] == provider_arn, (
        f"expected trust policy Federated principal {provider_arn}, got {before_delete!r}"
    )

    iam.delete_saml_provider(SAMLProviderArn=provider_arn)

    # The provider is now unreachable.
    get_code, get_message = _error(lambda: iam.get_saml_provider(SAMLProviderArn=provider_arn))
    assert get_code == "NoSuchEntity", (
        f"expected get_saml_provider on a deleted provider to raise NoSuchEntity, got {get_code!r}"
    )
    expected_get = f"Manifest not found for arn {provider_arn}"
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"

    # A deleted provider is not just unreadable -- it is also unusable as a
    # mutation target.
    update_code, update_message = _error(
        lambda: iam.update_saml_provider(
            SAMLProviderArn=provider_arn, SAMLMetadataDocument=metadata_document
        )
    )
    assert update_code == "NoSuchEntity", (
        f"expected update_saml_provider on a deleted provider to raise NoSuchEntity, got {update_code!r}"
    )
    expected_update = f"Manifest not found for arn {provider_arn}"
    assert update_message == expected_update, (
        f"expected message {expected_update!r}, got {update_message!r}"
    )

    # But the role's trust document is completely untouched -- no cascading
    # integrity check runs against role trust policies on provider deletion.
    after_delete = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert after_delete == before_delete, (
        f"expected trust policy unchanged by provider deletion: before={before_delete!r} after={after_delete!r}"
    )
    assert after_delete["Statement"][0]["Principal"]["Federated"] == provider_arn, (
        f"expected trust policy to still reference the deleted provider {provider_arn}, got {after_delete!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _self_signed_saml_metadata(name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    return (
        '<?xml version="1.0"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="https://{name}.example.com/idp">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing">'
        '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'<ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>'
        '</ds:KeyInfo></KeyDescriptor>'
        f'<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="https://{name}.example.com/sso"/>'
        '</IDPSSODescriptor></EntityDescriptor>'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
