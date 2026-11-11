"""grant-token-immediate-visibility."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "grant-token-immediate-visibility"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no KMS permission is denied Encrypt, then a fresh GrantToken lets it Encrypt
    immediately, before grant propagation; the grant eventually appears in ListGrants.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
    """
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kms-grantee-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grant-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # This role has zero attached IAM policies, so it starts with no path to kms:Encrypt.
    creds = _assume_role_with_retry(sts, role_arn, timeout_s=60.0)
    grantee_kms = ctx.client(
        "kms",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code_before, message_before = _error(
        lambda: grantee_kms.encrypt(KeyId=key_id, Plaintext=b"pre-grant-probe")
    )
    assert code_before == "AccessDeniedException", f"expected AccessDeniedException before grant, got {code_before}"
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"
    assert message_before == (
        f"User: {session_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        f"because no identity-based policy allows the kms:Encrypt action"
    ), f"unexpected message: {message_before!r}"

    grant = kms.create_grant(KeyId=key_id, GranteePrincipal=role_arn, Operations=["Encrypt"])
    grant_id = grant["GrantId"]
    grant_token = grant["GrantToken"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    # The fresh grant token authorizes immediate use -- no wait for grant propagation.
    resp = grantee_kms.encrypt(
        KeyId=key_id, Plaintext=b"grant-token-probe", GrantTokens=[grant_token]
    )
    assert resp["CiphertextBlob"], "expected Encrypt via grant token to succeed immediately"

    # Grants are eventually consistent; poll ListGrants.
    found = _poll_until(
        lambda: grant_id in {g["GrantId"] for g in kms.list_grants(KeyId=key_id).get("Grants", [])},
        lambda ok: ok,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert found, f"expected grant {grant_id} to eventually appear in ListGrants"


_SESSION_NAME = "sim2real-kms-grant"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assume_role_with_retry(sts, role_arn, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
            return resp["Credentials"]
        except Exception as err:  # IAM role creation has a brief propagation delay
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"role {role_arn} never became assumable: {last_err}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
