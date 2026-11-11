"""put-policy-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-policy-missing-permission-denied"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy from a principal with an explicit deny on acm-pca:PutPolicy fails with
    AccessDeniedException and attaches no policy; a privileged principal's identical call works."""
    acm = ctx.client("acm-pca")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    ca_arn = _create_ca(ctx)
    account_id = sts.get_caller_identity()["Account"]

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": [
                        "acm-pca:DescribeCertificateAuthority",
                        "acm-pca:GetCertificate",
                        "acm-pca:GetCertificateAuthorityCertificate",
                        "acm-pca:ListPermissions",
                        "acm-pca:ListTags",
                    ],
                    "Resource": ca_arn,
                }
            ],
        }
    )

    # A restricted IAM identity with an explicit deny on acm-pca:PutPolicy.
    user_name = ctx.unique_name("sim2real-pca-nopolicy-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_safely(ctx, user_name))
    deny_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "acm-pca:PutPolicy", "Resource": "*"}],
        }
    )
    iam.put_user_policy(UserName=user_name, PolicyName="deny-putpolicy", PolicyDocument=deny_doc)
    ctx.on_cleanup(lambda: _delete_user_policy_safely(ctx, user_name, "deny-putpolicy"))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: _delete_access_key_safely(ctx, user_name, key["AccessKeyId"]))

    restricted = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    def _restricted_put_policy():
        restricted.put_policy(ResourceArn=ca_arn, Policy=policy_doc)

    refusal = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        refusal = _error(_restricted_put_policy)
        # A freshly-created access key can briefly surface as unrecognized
        # (UnrecognizedClientException) or as an as-yet-unpropagated token
        # (InvalidClientTokenId) before IAM eventual consistency catches up.
        if refusal[0] not in ("InvalidClientTokenId", "UnrecognizedClientException"):
            break
        time.sleep(3.0)
    user_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
    assert refusal == (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: acm-pca:PutPolicy on resource: {ca_arn} "
        "with an explicit deny in an identity-based policy",
    ), refusal

    # effect absent: no resource policy was attached by the denied call
    no_policy = _error(lambda: acm.get_policy(ResourceArn=ca_arn))
    assert no_policy == ("ResourceNotFoundException", "Could not find policy for specified resource."), no_policy

    # positive control: the same PutPolicy call from a fully-privileged principal succeeds
    acm.put_policy(ResourceArn=ca_arn, Policy=policy_doc)
    ctx.on_cleanup(lambda: _delete_policy_safely(ctx, ca_arn))
    attached = acm.get_policy(ResourceArn=ca_arn)["Policy"]
    attached_doc = json.loads(attached)
    attached_stmt = attached_doc["Statement"][0]
    expected_stmt = json.loads(policy_doc)["Statement"][0]
    assert attached_stmt["Effect"] == expected_stmt["Effect"], (
        f"expected Effect={expected_stmt['Effect']!r}, attached policy has {attached_stmt['Effect']!r}"
    )
    assert set(attached_stmt["Action"]) == set(expected_stmt["Action"]), (
        f"expected Action set {set(expected_stmt['Action'])!r}, "
        f"attached policy has {set(attached_stmt['Action'])!r}"
    )
    # AWS normalizes the bare account-id Principal into a full IAM root ARN.
    assert account_id in json.dumps(attached_stmt["Principal"]), (
        f"expected account id {account_id!r} to appear in the attached Principal, "
        f"got {attached_stmt['Principal']!r}"
    )


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="acm-pca"):
    """A client signing AS the minted (restricted) principal against the same target as
    ``ctx.client``."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_ca(ctx, key_algorithm="RSA_2048", signing_algorithm="SHA256WITHRSA", ca_type="ROOT"):
    acm = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")
    resp = acm.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": key_algorithm,
            "SigningAlgorithm": signing_algorithm,
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType=ca_type,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    _wait_for_csr_ready(ctx, arn)
    return arn


def _delete_ca(ctx, arn):
    acm = ctx.client("acm-pca")
    try:
        acm.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_csr_ready(ctx, arn, timeout_s=90.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if status in ("PENDING_CERTIFICATE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError("CA never left CREATING state")


def _delete_policy_safely(ctx, resource_arn):
    acm = ctx.client("acm-pca")
    try:
        acm.delete_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_access_key_safely(ctx, user_name, access_key_id):
    iam = ctx.client("iam")
    try:
        iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_user_policy_safely(ctx, user_name, policy_name):
    iam = ctx.client("iam")
    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_user_safely(ctx, user_name):
    iam = ctx.client("iam")
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
