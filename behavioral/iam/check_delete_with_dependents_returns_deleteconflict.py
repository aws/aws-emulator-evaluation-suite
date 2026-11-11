"""delete-with-dependents-returns-deleteconflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-with-dependents-returns-deleteconflict"
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


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _totp_code(secret_b32, offset_steps=0, step=30, digits=6):
    import base64
    import hashlib
    import hmac
    import struct
    import time

    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    counter = int(time.time() // step) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an IAM entity that still has a dependent fails DeleteConflict and it survives; once
    the dependent is removed the same delete succeeds. A server certificate is the no-dependent case."""
    iam = ctx.client("iam")

    tags = [{"Key": "sim2real", "Value": CHECK}]

    # Group with a member.
    group_name = ctx.unique_name("sim2real-behav-group-")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_group(GroupName=group_name)))
    iam.create_user(UserName=user_name, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_user(UserName=user_name)))
    iam.add_user_to_group(GroupName=group_name, UserName=user_name)
    code_group, code_group_msg = _client_error(lambda: iam.delete_group(GroupName=group_name))
    assert code_group == "DeleteConflict", f"DeleteGroup: expected DeleteConflict, got {code_group}"
    assert code_group_msg == "Cannot delete entity, must remove users from group first.", f"unexpected error message {code_group_msg!r}"
    iam.remove_user_from_group(GroupName=group_name, UserName=user_name)
    iam.delete_group(GroupName=group_name)
    code_group2, code_group2_msg = _client_error(lambda: iam.get_group(GroupName=group_name))
    assert code_group2 == "NoSuchEntity", "group should be gone once its only dependent is removed"
    assert code_group2_msg == f"The group with name {group_name} cannot be found.", f"unexpected error message {code_group2_msg!r}"

    # Role with an inline policy.
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_POLICY_EC2, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline", PolicyDocument=ALLOW_S3_LIST_POLICY
    )
    code_role, code_role_msg = _client_error(lambda: iam.delete_role(RoleName=role_name))
    assert code_role == "DeleteConflict", f"DeleteRole: expected DeleteConflict, got {code_role}"
    assert code_role_msg == "Cannot delete entity, must delete policies first.", f"unexpected error message {code_role_msg!r}"
    iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline")
    iam.delete_role(RoleName=role_name)
    code_role2, code_role2_msg = _client_error(lambda: iam.get_role(RoleName=role_name))
    assert code_role2 == "NoSuchEntity", "role should be gone once its only dependent is removed"
    assert code_role2_msg == f"The role with name {role_name} cannot be found.", f"unexpected error message {code_role2_msg!r}"

    # User with an attached managed policy.
    user2 = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user2, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_user(UserName=user2)))
    policy_name1 = ctx.unique_name("sim2real-behav-policy-")
    policy_arn1 = iam.create_policy(
        PolicyName=policy_name1, PolicyDocument=ALLOW_S3_LIST_POLICY, Tags=tags
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_policy(PolicyArn=policy_arn1)))
    iam.attach_user_policy(UserName=user2, PolicyArn=policy_arn1)
    code_user, code_user_msg = _client_error(lambda: iam.delete_user(UserName=user2))
    assert code_user == "DeleteConflict", f"DeleteUser: expected DeleteConflict, got {code_user}"
    assert code_user_msg == "Cannot delete entity, must detach all policies first.", f"unexpected error message {code_user_msg!r}"
    iam.detach_user_policy(UserName=user2, PolicyArn=policy_arn1)
    iam.delete_user(UserName=user2)
    code_user2, code_user2_msg = _client_error(lambda: iam.get_user(UserName=user2))
    assert code_user2 == "NoSuchEntity", "user should be gone once its only dependent is removed"
    assert code_user2_msg == f"The user with name {user2} cannot be found.", f"unexpected error message {code_user2_msg!r}"

    # Managed policy still attached to an entity.
    user3 = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user3, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_user(UserName=user3)))
    policy_name2 = ctx.unique_name("sim2real-behav-policy-")
    policy_arn2 = iam.create_policy(
        PolicyName=policy_name2, PolicyDocument=ALLOW_S3_LIST_POLICY, Tags=tags
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_policy(PolicyArn=policy_arn2)))
    iam.attach_user_policy(UserName=user3, PolicyArn=policy_arn2)
    code_policy, code_policy_msg = _client_error(lambda: iam.delete_policy(PolicyArn=policy_arn2))
    assert code_policy == "DeleteConflict", f"DeletePolicy: expected DeleteConflict, got {code_policy}"
    assert code_policy_msg == "Cannot delete a policy attached to entities.", f"unexpected error message {code_policy_msg!r}"
    iam.detach_user_policy(UserName=user3, PolicyArn=policy_arn2)
    iam.delete_policy(PolicyArn=policy_arn2)
    code_policy2, code_policy2_msg = _client_error(lambda: iam.get_policy(PolicyArn=policy_arn2))
    assert code_policy2 == "NoSuchEntity", "policy should be gone once its only dependent is removed"
    assert code_policy2_msg == f"Policy {policy_arn2} was not found.", f"unexpected error message {code_policy2_msg!r}"

    # PolicyVersion: the CURRENT DEFAULT version can never be deleted directly.
    policy_name3 = ctx.unique_name("sim2real-behav-policy-")
    created3 = iam.create_policy(
        PolicyName=policy_name3, PolicyDocument=ALLOW_S3_LIST_POLICY, Tags=tags
    )
    policy_arn3 = created3["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_policy(PolicyArn=policy_arn3)))
    v1 = created3["Policy"]["DefaultVersionId"]
    code_pv, code_pv_msg = _client_error(lambda: iam.delete_policy_version(PolicyArn=policy_arn3, VersionId=v1))
    assert code_pv == "DeleteConflict", f"DeletePolicyVersion: expected DeleteConflict, got {code_pv}"
    assert code_pv_msg == "Cannot delete the default version of a policy.", f"unexpected error message {code_pv_msg!r}"
    versions_after_reject = {
        v["VersionId"]: v for v in iam.list_policy_versions(PolicyArn=policy_arn3)["Versions"]
    }
    assert v1 in versions_after_reject, "policy version should survive a rejected delete"
    assert versions_after_reject[v1]["IsDefaultVersion"] is True, (
        "rejected delete must not change which version is default"
    )
    # Demote v1 by making a new version the default -- the SAME delete call must now succeed.
    v2 = iam.create_policy_version(
        PolicyArn=policy_arn3, PolicyDocument=ALLOW_S3_LIST_POLICY, SetAsDefault=True
    )["PolicyVersion"]["VersionId"]
    iam.delete_policy_version(PolicyArn=policy_arn3, VersionId=v1)
    versions_after_demote = {
        v["VersionId"] for v in iam.list_policy_versions(PolicyArn=policy_arn3)["Versions"]
    }
    assert v1 not in versions_after_demote, "policy version should be gone once demoted and deleted"
    assert v2 in versions_after_demote, "the new default version must remain"

    # InstanceProfile with a role attached.
    profile_name = ctx.unique_name("sim2real-behav-profile-")
    role4 = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role4, AssumeRolePolicyDocument=TRUST_POLICY_EC2, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role4)))
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role4)
    code_ip, code_ip_msg = _client_error(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    assert code_ip == "DeleteConflict", f"DeleteInstanceProfile: expected DeleteConflict, got {code_ip}"
    assert code_ip_msg == "Cannot delete entity, must remove roles from instance profile first.", f"unexpected error message {code_ip_msg!r}"
    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role4)
    iam.delete_instance_profile(InstanceProfileName=profile_name)
    code_ip2, code_ip2_msg = _client_error(lambda: iam.get_instance_profile(InstanceProfileName=profile_name))
    assert code_ip2 == "NoSuchEntity", "instance profile should be gone once its role is removed"
    assert code_ip2_msg == f"Instance Profile {profile_name} cannot be found.", f"unexpected error message {code_ip2_msg!r}"

    # ServerCertificate: no dependent is reachable through IAM alone; confirm the baseline delete.
    server_cert_pem, server_key_pem = _gen_self_signed_cert("sim2real-behav-server-cert")
    server_name = ctx.unique_name("sim2real-behav-servercert-")
    iam.upload_server_certificate(
        ServerCertificateName=server_name,
        CertificateBody=server_cert_pem,
        PrivateKey=server_key_pem,
        Tags=tags,
    )
    iam.delete_server_certificate(ServerCertificateName=server_name)
    code_sc, code_sc_msg = _client_error(lambda: iam.get_server_certificate(ServerCertificateName=server_name))
    assert code_sc == "NoSuchEntity", "server certificate with no dependents should delete cleanly"
    assert code_sc_msg == f"The Server Certificate with name {server_name} cannot be found.", f"unexpected error message {code_sc_msg!r}"

    # Virtual MFA device currently assigned/enabled on a user.
    user5 = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user5, Tags=tags)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_user(UserName=user5)))
    device_name = ctx.unique_name("sim2real-behav-mfa-")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name, Tags=tags)
    serial = device["VirtualMFADevice"]["SerialNumber"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial)))
    seed_raw = device["VirtualMFADevice"]["Base32StringSeed"]
    seed = seed_raw.decode("ascii") if isinstance(seed_raw, bytes) else seed_raw
    code1 = _totp_code(seed, offset_steps=0)
    code2 = _totp_code(seed, offset_steps=1)
    iam.enable_mfa_device(
        UserName=user5, SerialNumber=serial, AuthenticationCode1=code1, AuthenticationCode2=code2
    )
    code_mfa, code_mfa_msg = _client_error(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))
    assert code_mfa == "DeleteConflict", f"DeleteVirtualMFADevice: expected DeleteConflict, got {code_mfa}"
    assert code_mfa_msg == "MFA VirtualDevice in use. Must deactivate first.", f"unexpected error message {code_mfa_msg!r}"
    iam.deactivate_mfa_device(UserName=user5, SerialNumber=serial)
    iam.delete_virtual_mfa_device(SerialNumber=serial)
    remaining = [d["SerialNumber"] for d in iam.list_virtual_mfa_devices()["VirtualMFADevices"]]
    assert serial not in remaining, "MFA device should be gone once deactivated and deleted"


def _ignore_missing(fn):
    """Teardown: run fn(), tolerating only NoSuchEntity for a resource the check already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
