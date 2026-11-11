"""non-user-caller-must-specify-username-rejected."""
from __future__ import annotations

import json
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "non-user-caller-must-specify-username-rejected"
GROUP = "errors"
SERVICES = ["iam"]

_SELF_POLICY_NAME = "sim2real-behav-self-signing-cert"


def _error_code(fn):
    """The AWS error code fn() fails with; raise when it succeeds, so an over-permissive target
    fails as an unexpected success rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(ctx, fn, pred, timeout_s=60, interval_s=2):
    """Retry fn() until pred(outcome) is truthy; outcome is the AWS error code or the result."""
    deadline = time.monotonic() + timeout_s
    outcome = fn()
    while not pred(outcome):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not observed within {timeout_s}s; last saw {outcome!r}")
        time.sleep(interval_s)
        outcome = fn()
    return outcome


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Omitting UserName on signing-certificate calls resolves to the signing IAM user, but an
    authorized assumed-role caller gets ValidationError "Must specify userName when calling with
    non-User credentials"; the user's implicit resolution is unaffected afterwards.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListSigningCertificates.html
    """
    iam = ctx.client("iam")
    account_id = ctx.account

    # --- Positive control: a genuine IAM user, scoped to manage only ITS OWN signing
    # certificates, gets its UserName resolved implicitly when the field is omitted.
    user_name = ctx.unique_name("sim2real-behav-selfcert-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    self_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "iam:UploadSigningCertificate",
                "iam:ListSigningCertificates",
                "iam:DeleteSigningCertificate",
            ],
            "Resource": f"arn:aws:iam::{account_id}:user/${{aws:username}}",
        }],
    })
    iam.put_user_policy(UserName=user_name, PolicyName=_SELF_POLICY_NAME, PolicyDocument=self_policy)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=_SELF_POLICY_NAME))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = access_key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))

    self_client = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": key_id,
            "aws_secret_access_key": access_key["SecretAccessKey"],
        },
    )
    cert_pem = _self_signed_cert_pem(ctx, common_name="sim2real-behav-usernameoptional.example.com")

    # A brand-new access key is replicated per-replica before it authenticates; the self-managed
    # identity policy is also freshly attached. Poll the actual signed call rather than sleeping a
    # fixed guess, and never treat a mid-propagation error as the ValidationError under test.
    uploaded = _poll_until(
        ctx,
        lambda: _try_upload(self_client, cert_pem),
        lambda outcome: outcome not in ("InvalidClientTokenId", "AccessDenied"),
    )
    assert isinstance(uploaded, dict), (
        f"expected the self-signed-in IAM user's UploadSigningCertificate (no UserName) to "
        f"eventually succeed via implicit resolution, got error code {uploaded!r}"
    )
    cert_id = uploaded["CertificateId"]
    assert uploaded["UserName"] == user_name, (
        f"implicit resolution must bind the omitted UserName to the SIGNING user {user_name!r}, "
        f"got {uploaded['UserName']!r}"
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)
        )
    )

    listed = {c["CertificateId"]: c for c in self_client.list_signing_certificates()["Certificates"]}
    assert cert_id in listed, (
        f"ListSigningCertificates with no UserName, signed by the same IAM user, must resolve to "
        f"the identical implied identity and show the cert it just uploaded; got {sorted(listed)!r}"
    )
    assert listed[cert_id]["UserName"] == user_name, (
        f"the listed certificate's UserName must also resolve to {user_name!r}, got "
        f"{listed[cert_id]['UserName']!r}"
    )

    # --- The actual negative: a non-User (assumed-role) caller, fully authorized for the
    # operation, omitting UserName is rejected -- it is not just under-permissioned.
    role_name = ctx.unique_name("sim2real-behav-nonuser-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    })
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:ListSigningCertificates", "Resource": "*"}],
    })
    iam.put_role_policy(RoleName=role_name, PolicyName="allow-list-signing-certs", PolicyDocument=role_policy)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-list-signing-certs"))

    sts = ctx.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # Trust and permission propagation on a just-created role; poll the actual AssumeRole+call
    # path rather than sleeping a fixed guess.
    assumed_outcome = _poll_until(
        ctx,
        lambda: _try_assume_and_call(ctx, sts, role_arn),
        lambda outcome: outcome != "ASSUME_FAILED",
    )
    expected = ("ValidationError", "Must specify userName when calling with non-User credentials")
    assert assumed_outcome == expected, (
        f"a non-User (assumed-role) caller omitting UserName must be rejected {expected!r} -- "
        f"it is fully authorized for ListSigningCertificates, so this is implicit-resolution's own "
        f"refusal, not an authorization failure; got {assumed_outcome!r}"
    )

    # --- The implicit-resolution path for the genuine IAM user is unaffected by the role's
    # rejection: the identical self-call still succeeds afterward.
    still_listed = {c["CertificateId"] for c in self_client.list_signing_certificates()["Certificates"]}
    assert cert_id in still_listed, (
        f"the IAM user's own implicit-resolution listing must still include {cert_id!r} after the "
        f"unrelated non-User rejection, got {sorted(still_listed)!r}"
    )


def _try_upload(client, cert_pem: str):
    """The certificate dict on success, else the AWS error code; never raises."""
    try:
        return client.upload_signing_certificate(CertificateBody=cert_pem)["Certificate"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"


def _try_assume_and_call(ctx, sts, role_arn: str):
    """Assume the role afresh and call ListSigningCertificates with no UserName.

    "ASSUME_FAILED" while trust is propagating, else the IAM (code, message); a success raises."""
    try:
        creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-probe")["Credentials"]
    except ClientError:
        return "ASSUME_FAILED"
    role_client = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    try:
        result = role_client.list_signing_certificates()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
        if code in ("InvalidClientTokenId", "AccessDenied"):
            return "ASSUME_FAILED"
        return code, exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected a non-User caller omitting UserName to be rejected, but it SUCCEEDED: {result!r}"
    )


def _ignore_no_such_entity(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _self_signed_cert_pem(ctx, common_name: str) -> str:
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
    return combined[cert_start:cert_end].strip() + "\n"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
