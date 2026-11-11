"""get-nonexistent-entity-returns-nosuchentity."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-entity-returns-nosuchentity"
GROUP = 'errors'
SERVICES = ['iam']

ALLOW_S3_LIST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _expect(label, fn, code, message):
    """Assert fn() is rejected with exactly this code and exactly this message."""
    got_code, got_message = _error(fn)
    assert got_code == code, f"{label}: expected {code}, got {got_code}"
    assert got_message == message, f"{label}: expected message {message!r}, got {got_message!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get* on a nonexistent entity returns NoSuchEntity (not a generic error) for each entity kind;
    GetMFADevice instead rejects a non-FIDO SerialNumber with ValidationError before any lookup."""
    iam = ctx.client("iam")
    account_id = _account_id(ctx)

    no_user = ctx.unique_name("sim2real-behav-nouser-")
    _expect(
        "GetUser",
        lambda: iam.get_user(UserName=no_user),
        "NoSuchEntity",
        f"The user with name {no_user} cannot be found.",
    )

    no_group = ctx.unique_name("sim2real-behav-nogroup-")
    _expect(
        "GetGroup",
        lambda: iam.get_group(GroupName=no_group),
        "NoSuchEntity",
        f"The group with name {no_group} cannot be found.",
    )

    no_role = ctx.unique_name("sim2real-behav-norole-")
    _expect(
        "GetRole",
        lambda: iam.get_role(RoleName=no_role),
        "NoSuchEntity",
        f"The role with name {no_role} cannot be found.",
    )

    fake_policy_arn = f"arn:aws:iam::{account_id}:policy/{ctx.unique_name('sim2real-behav-nopolicy-')}"
    _expect(
        "GetPolicy",
        lambda: iam.get_policy(PolicyArn=fake_policy_arn),
        "NoSuchEntity",
        f"Policy {fake_policy_arn} was not found.",
    )

    # GetPolicyVersion: a REAL policy, but a version id that was never created.
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    real_policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=ALLOW_S3_LIST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=real_policy_arn))

    # Positive control: the SAME two Get ops, issued against the entity that DOES exist, must
    # succeed. Without this leg a target that unconditionally answers NoSuchEntity for every
    # Get* call — never actually checking existence — passes every assertion below it.
    got_policy = iam.get_policy(PolicyArn=real_policy_arn)["Policy"]
    assert got_policy["PolicyName"] == policy_name, (
        f"GetPolicy on the just-created policy: expected {policy_name!r}, got {got_policy!r}"
    )
    got_version = iam.get_policy_version(PolicyArn=real_policy_arn, VersionId="v1")["PolicyVersion"]
    assert got_version["VersionId"] == "v1", (
        f"GetPolicyVersion on the just-created policy's initial version: expected 'v1', got {got_version!r}"
    )

    _expect(
        "GetPolicyVersion",
        lambda: iam.get_policy_version(PolicyArn=real_policy_arn, VersionId="v9"),
        "NoSuchEntity",
        f"Policy {real_policy_arn} version v9 does not exist or is not attachable.",
    )

    no_profile = ctx.unique_name("sim2real-behav-noprofile-")
    _expect(
        "GetInstanceProfile",
        lambda: iam.get_instance_profile(InstanceProfileName=no_profile),
        "NoSuchEntity",
        f"Instance Profile {no_profile} cannot be found.",
    )

    fake_oidc_arn = f"arn:aws:iam::{account_id}:oidc-provider/sim2real-behav-{uuid.uuid4().hex}.example.com"
    _expect(
        "GetOpenIDConnectProvider",
        lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=fake_oidc_arn),
        "NoSuchEntity",
        f"OpenIDConnect Provider not found for arn {fake_oidc_arn}",
    )

    fake_saml_arn = f"arn:aws:iam::{account_id}:saml-provider/{ctx.unique_name('sim2real-behav-nosaml-')}"
    _expect(
        "GetSAMLProvider",
        lambda: iam.get_saml_provider(SAMLProviderArn=fake_saml_arn),
        "NoSuchEntity",
        f"Manifest not found for arn {fake_saml_arn}",
    )

    no_cert = ctx.unique_name("sim2real-behav-nocert-")
    _expect(
        "GetServerCertificate",
        lambda: iam.get_server_certificate(ServerCertificateName=no_cert),
        "NoSuchEntity",
        f"The Server Certificate with name {no_cert} cannot be found.",
    )

    no_lp_user = ctx.unique_name("sim2real-behav-nouser-")
    _expect(
        "GetLoginProfile",
        lambda: iam.get_login_profile(UserName=no_lp_user),
        "NoSuchEntity",
        f"The user with name {no_lp_user} cannot be found.",
    )

    # GetMFADevice only accepts FIDO security-key ARNs. A made-up-but-ARN-shaped value that
    # doesn't match the exact FIDO grammar is rejected ValidationError BEFORE any existence check.
    fake_fido_arn = f"arn:aws:iam::{account_id}:u2f/user/{ctx.unique_name('sim2real-behav-nouser-')}/sim2real-behav-fido"
    _expect(
        "GetMFADevice",
        lambda: iam.get_mfa_device(SerialNumber=fake_fido_arn),
        "ValidationError",
        "The MFA device serial number sent in the request is invalid or not supported by this API. "
        "Currently, only hardware FIDO security keys are supported. "
        "Please use the compatible device or API.",
    )

    no_ssh_user = ctx.unique_name("sim2real-behav-nouser-")
    ssh_key_id = uuid.uuid4().hex
    _expect(
        "GetSSHPublicKey",
        lambda: iam.get_ssh_public_key(UserName=no_ssh_user, SSHPublicKeyId=ssh_key_id, Encoding="SSH"),
        "NoSuchEntity",
        f"The user with name {no_ssh_user} cannot be found.",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
