"""cmk-key-policy-granting-only-decrypt-lets-a-role-read-but-refuses-its-write."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cmk-key-policy-granting-only-decrypt-lets-a-role-read-but-refuses-its-write"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-cmk-writer"
_CREDENTIAL_PROPAGATION = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)
_WRITE_TOKEN = "sim2real-cmk-write-0000000000000001"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role allowed Get/PutSecretValue but granted only kms:Decrypt by the CMK's key policy reads
    the secret and is refused the write, which mints no version; adding kms:GenerateDataKey lets the
    identical write land and the role reads its own value.
    """
    sm = ctx.client("secretsmanager")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-cmk-role-")
    role_arn = _create_role(ctx, iam, account_id, role_name)

    def key_policy(role_actions):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AccountAdministers",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "RoleUse",
                        "Effect": "Allow",
                        "Principal": {"AWS": role_arn},
                        "Action": role_actions,
                        "Resource": "*",
                    },
                ],
            }
        )

    key_id = _create_key(ctx, kms, key_policy(["kms:Decrypt"]))

    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-cmk-secret-"),
        SecretString="original",
        KmsKeyId=key_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    original_version = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="secret-rw",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"],
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="secret-rw"))
    as_role = _client_as(ctx, _assume(sts, role_arn))

    # Read works: Secrets Manager grant plus kms:Decrypt from the key policy.
    read = _poll(
        lambda: _call(lambda: as_role.get_secret_value(SecretId=secret_arn)["SecretString"]),
        lambda r: r[0] == "ok",
        timeout_s=90.0,
        interval_s=3.0,
        description="the role's read grant to become effective",
    )
    assert read == ("ok", "original"), f"the role must read through kms:Decrypt; got {read!r}"

    def write():
        return as_role.put_secret_value(
            SecretId=secret_arn, SecretString="written-by-role", ClientRequestToken=_WRITE_TOKEN
        )["VersionId"]

    refused = _call(write)
    assert refused == (
        "error",
        "AccessDeniedException",
        "Access to KMS is not allowed",
    ), f"a write without kms:GenerateDataKey on the key must be refused; got {refused!r}"

    versions = _version_map(sm, secret_arn)
    assert versions == {original_version: ["AWSCURRENT"]}, (
        f"the refused write must mint no version; versions are {versions!r}"
    )
    assert sm.get_secret_value(SecretId=secret_arn)["SecretString"] == "original", (
        "the refused write must leave the current value untouched"
    )

    # Grant the missing key permission; the identical write then lands.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=key_policy(["kms:Decrypt", "kms:GenerateDataKey"]))
    landed = _poll(
        lambda: _call(write),
        lambda r: r[0] == "ok",
        timeout_s=90.0,
        interval_s=3.0,
        description="the key-policy change to permit the role's write",
    )
    assert landed == ("ok", _WRITE_TOKEN), f"the write must land under its token; got {landed!r}"
    versions = _version_map(sm, secret_arn)
    assert versions == {original_version: ["AWSPREVIOUS"], _WRITE_TOKEN: ["AWSCURRENT"]}, (
        f"the permitted write must become AWSCURRENT over the original; versions are {versions!r}"
    )
    # The current-value read is eventually consistent after a write: converge, never require lag.
    reread = _poll(
        lambda: _call(lambda: as_role.get_secret_value(SecretId=secret_arn)["SecretString"]),
        lambda r: r == ("ok", "written-by-role"),
        timeout_s=60.0,
        interval_s=2.0,
        description="the role's read to converge on its own write",
    )
    assert reread == ("ok", "written-by-role"), f"the role must read its own write; got {reread!r}"


def _create_role(ctx, iam, account_id, role_name):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Role"]["Arn"]


def _create_key(ctx, kms, policy, timeout_s=60.0, interval_s=3.0):
    """A key whose policy names the new role; KMS refuses a principal IAM has not propagated yet."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            key = kms.create_key(
                Description="sim2real-behav key for " + CHECK,
                Policy=policy,
                Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "MalformedPolicyDocumentException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the key policy naming the new role was never accepted: {exc}")
            time.sleep(interval_s)
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _assume(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_as(ctx, creds):
    return ctx.client(
        "secretsmanager",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _call(fn):
    try:
        return ("ok", fn())
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return ("error", error.get("Code"), error.get("Message"))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) or (last[0] == "error" and last[1] in _CREDENTIAL_PROPAGATION):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _version_map(sm, secret_arn):
    out = {}
    kwargs = {"SecretId": secret_arn}
    while True:
        page = sm.list_secret_version_ids(**kwargs)
        for v in page["Versions"]:
            out[v["VersionId"]] = sorted(v.get("VersionStages", []))
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
