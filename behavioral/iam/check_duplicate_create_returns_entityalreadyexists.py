"""duplicate-create-returns-entityalreadyexists."""
from __future__ import annotations

import hashlib
import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-create-returns-entityalreadyexists"
GROUP = 'errors'
SERVICES = ['iam']

TRUST_POLICY_EC2 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

ALLOW_S3_LIST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)

ALLOW_S3_GET_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


def _error(fn):
    """Call fn(); return the botocore (code, message). An unexpected success raises, so an
    accepted duplicate create cannot read as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _random_thumbprint():
    """A syntactically valid (40 hex char) SHA1-shaped thumbprint. IAM stores OIDC thumbprints
    verbatim; it does not dial the URL to verify them against a live TLS cert."""
    return hashlib.sha1(uuid.uuid4().bytes).hexdigest()


def _gen_self_signed_cert(common_name, days=3650):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def _gen_saml_metadata_document(entity_id, sso_host, cert_pem):
    cert_b64 = "".join(
        line for line in cert_pem.strip().splitlines() if not line.startswith("-----")
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EntityDescriptor entityID="{entity_id}" '
        'xmlns="urn:oasis:names:tc:SAML:2.0:metadata">\n'
        '  <IDPSSODescriptor WantAuthnRequestsSigned="false" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        '    <KeyDescriptor use="signing">\n'
        '      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\n'
        "        <X509Data>\n"
        f"          <X509Certificate>{cert_b64}</X509Certificate>\n"
        "        </X509Data>\n"
        "      </KeyInfo>\n"
        "    </KeyDescriptor>\n"
        "    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n"
        '    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="https://{sso_host}/sso"/>\n'
        "  </IDPSSODescriptor>\n"
        "</EntityDescriptor>\n"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-account-alias")
def run(ctx) -> None:
    """Every Create* op with a natural duplicate case (name, URL, or singleton) returns
    EntityAlreadyExists on a re-create, and the original entity's identity is left untouched."""
    iam = ctx.client("iam")

    # User
    user_name = ctx.unique_name("sim2real-behav-user-")
    user_id = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "User"
    ]["UserId"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    code_user, msg_user = _error(lambda: iam.create_user(UserName=user_name))
    assert code_user == "EntityAlreadyExists", f"CreateUser: expected EntityAlreadyExists, got {code_user}"
    assert msg_user == f"User with name {user_name} already exists.", f"user: unexpected message {msg_user!r}"
    assert iam.get_user(UserName=user_name)["User"]["UserId"] == user_id

    # Group (no Tags parameter exists for CreateGroup -- IAM groups are not a taggable resource)
    group_name = ctx.unique_name("sim2real-behav-group-")
    group_id = iam.create_group(GroupName=group_name)["Group"]["GroupId"]
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))
    code_group, msg_group = _error(lambda: iam.create_group(GroupName=group_name))
    assert code_group == "EntityAlreadyExists", f"CreateGroup: expected EntityAlreadyExists, got {code_group}"
    assert msg_group == f"Group with name {group_name} already exists.", f"group: unexpected message {msg_group!r}"
    assert iam.get_group(GroupName=group_name)["Group"]["GroupId"] == group_id

    # Role
    role_name = ctx.unique_name("sim2real-behav-role-")
    role_id = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=TRUST_POLICY_EC2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["RoleId"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    code_role, msg_role = _error(
        lambda: iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_POLICY_EC2)
    )
    assert code_role == "EntityAlreadyExists", f"CreateRole: expected EntityAlreadyExists, got {code_role}"
    assert msg_role == f"Role with name {role_name} already exists.", f"role: unexpected message {msg_role!r}"
    assert iam.get_role(RoleName=role_name)["Role"]["RoleId"] == role_id

    # Policy
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=ALLOW_S3_LIST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    code_policy, msg_policy = _error(
        lambda: iam.create_policy(PolicyName=policy_name, PolicyDocument=ALLOW_S3_GET_POLICY)
    )
    assert code_policy == "EntityAlreadyExists", f"CreatePolicy: expected EntityAlreadyExists, got {code_policy}"
    assert msg_policy == f"A policy called {policy_name} already exists. Duplicate names are not allowed.", f"policy: unexpected message {msg_policy!r}"
    # The rejected attempt (with a DIFFERENT document) must not have mutated the original.
    doc = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"],
    )["PolicyVersion"]["Document"]
    assert doc["Statement"][0]["Action"] == "s3:ListBucket", "rejected duplicate CreatePolicy must not overwrite"

    # InstanceProfile
    profile_name = ctx.unique_name("sim2real-behav-profile-")
    profile_id = iam.create_instance_profile(
        InstanceProfileName=profile_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["InstanceProfile"]["InstanceProfileId"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    code_ip, msg_ip = _error(lambda: iam.create_instance_profile(InstanceProfileName=profile_name))
    assert code_ip == "EntityAlreadyExists", f"CreateInstanceProfile: expected EntityAlreadyExists, got {code_ip}"
    assert msg_ip == f"Instance Profile {profile_name} already exists.", f"ip: unexpected message {msg_ip!r}"
    assert (
        iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"][
            "InstanceProfileId"
        ]
        == profile_id
    )

    # OIDC provider (keyed by Url, not a name)
    oidc_host = f"sim2real-behav-oidc-{uuid.uuid4().hex[:12]}.example.com"
    oidc_url = f"https://{oidc_host}"
    oidc_thumbprint = _random_thumbprint()
    oidc_arn = iam.create_open_id_connect_provider(
        Url=oidc_url,
        ThumbprintList=[oidc_thumbprint],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=oidc_arn))
    code_oidc, msg_oidc = _error(
        lambda: iam.create_open_id_connect_provider(
            Url=oidc_url, ThumbprintList=[_random_thumbprint()]
        )
    )
    assert code_oidc == "EntityAlreadyExists", (
        f"CreateOpenIDConnectProvider: expected EntityAlreadyExists, got {code_oidc}"
    )
    assert msg_oidc == f"Provider with url {oidc_url} already exists.", f"oidc: unexpected message {msg_oidc!r}"
    # effect absent: still exactly one provider at this URL, and its thumbprint (a DIFFERENT
    # value was offered by the rejected duplicate) is untouched.
    oidc_providers = iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
    assert sum(1 for p in oidc_providers if p["Arn"] == oidc_arn) == 1, (
        f"expected exactly one OIDC provider at {oidc_arn!r}, saw {oidc_providers!r}"
    )
    assert iam.get_open_id_connect_provider(OpenIDConnectProviderArn=oidc_arn)[
        "ThumbprintList"
    ] == [oidc_thumbprint], "rejected duplicate CreateOpenIDConnectProvider must not overwrite the thumbprint"

    # SAML provider
    saml_name = ctx.unique_name("sim2real-behav-saml-")
    saml_host = f"sim2real-behav-saml-{uuid.uuid4().hex[:12]}.example.com"
    cert_pem, _ = _gen_self_signed_cert(saml_host)
    metadata = _gen_saml_metadata_document(f"https://{saml_host}/entity", saml_host, cert_pem)
    saml_arn = iam.create_saml_provider(
        SAMLMetadataDocument=metadata,
        Name=saml_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=saml_arn))
    code_saml, msg_saml = _error(
        lambda: iam.create_saml_provider(SAMLMetadataDocument=metadata, Name=saml_name)
    )
    assert code_saml == "EntityAlreadyExists", f"CreateSAMLProvider: expected EntityAlreadyExists, got {code_saml}"
    assert msg_saml == f"Provider with name {saml_name} already exists.", f"saml: unexpected message {msg_saml!r}"
    # effect absent: still exactly one provider with this ARN (Name is embedded in it).
    saml_providers = iam.list_saml_providers()["SAMLProviderList"]
    assert sum(1 for p in saml_providers if p["Arn"] == saml_arn) == 1, (
        f"expected exactly one SAML provider at {saml_arn!r}, saw {saml_providers!r}"
    )

    # Login profile (reuse the user created above)
    iam.create_login_profile(UserName=user_name, Password="Sim2Real!Behav1")
    ctx.on_cleanup(lambda: iam.delete_login_profile(UserName=user_name))
    login_created_at = iam.get_login_profile(UserName=user_name)["LoginProfile"]["CreateDate"]
    code_lp, msg_lp = _error(
        lambda: iam.create_login_profile(UserName=user_name, Password="Sim2Real!Behav2")
    )
    assert code_lp == "EntityAlreadyExists", f"CreateLoginProfile: expected EntityAlreadyExists, got {code_lp}"
    assert msg_lp == f"Login Profile for user {user_name} already exists.", f"lp: unexpected message {msg_lp!r}"
    # effect absent: GetLoginProfile never echoes the password, so creation time is the
    # available proxy for "the rejected duplicate did not replace it".
    assert (
        iam.get_login_profile(UserName=user_name)["LoginProfile"]["CreateDate"] == login_created_at
    ), "rejected duplicate CreateLoginProfile must not replace the existing login profile"

    # Virtual MFA device
    device_name = ctx.unique_name("sim2real-behav-mfa-")
    serial = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=device_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["VirtualMFADevice"]["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))
    code_mfa, msg_mfa = _error(lambda: iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name))
    assert code_mfa == "EntityAlreadyExists", (
        f"CreateVirtualMFADevice: expected EntityAlreadyExists, got {code_mfa}"
    )
    assert msg_mfa == "MFA device already exists.", f"mfa: unexpected message {msg_mfa!r}"
    # effect absent: exactly one device carries this name, and it's still the original serial.
    mfa_devices = iam.list_virtual_mfa_devices()["VirtualMFADevices"]
    matching_mfa = [d for d in mfa_devices if d["SerialNumber"].endswith(f"/{device_name}")]
    assert len(matching_mfa) == 1 and matching_mfa[0]["SerialNumber"] == serial, (
        f"expected exactly one device named {device_name!r} with serial {serial!r}, got {matching_mfa!r}"
    )

    # Account alias: an account-wide singleton. Snapshot the slot and restore the original on
    # cleanup. (No Tags parameter exists for CreateAccountAlias -- account aliases are not a
    # taggable resource.)
    original_aliases = iam.list_account_aliases()["AccountAliases"]
    alias = ctx.unique_name("sim2real-behav-alias-").lower()
    ctx.on_cleanup(lambda: _restore_alias(iam, original_aliases, alias))
    iam.create_account_alias(AccountAlias=alias)
    code_alias, msg_alias = _error(lambda: iam.create_account_alias(AccountAlias=alias))
    assert code_alias == "EntityAlreadyExists", (
        f"CreateAccountAlias: expected EntityAlreadyExists, got {code_alias}"
    )
    assert msg_alias == f"The account alias {alias} already exists.", f"alias: unexpected message {msg_alias!r}"
    # effect absent: the account still holds exactly the one alias we created.
    assert iam.list_account_aliases()["AccountAliases"] == [alias], (
        "rejected duplicate CreateAccountAlias must not change the account's alias"
    )


def _restore_alias(iam, original, ours):
    """Put the account alias slot back to the snapshot taken before the check wrote it."""
    current = iam.list_account_aliases()["AccountAliases"]
    if original:
        if current != original:
            iam.create_account_alias(AccountAlias=original[0])
    elif ours in current:
        iam.delete_account_alias(AccountAlias=ours)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
