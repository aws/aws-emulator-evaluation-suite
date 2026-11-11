"""encryption-context-parameter-arn-condition-scopes-decryption."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encryption-context-parameter-arn-condition-scopes-decryption"
GROUP = "parameter-store"
SERVICES = ["kms", "ssm"]

_ACCEPTED = "<call succeeded>"


def _error(fn):
    """Return (code, message) from the ClientError fn raises, or (_ACCEPTED, "") on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    return _ACCEPTED, ""


def _assume_role_with_retry(sts, role_arn, session_name, attempts=10, delay_s=3.0):
    """IAM role-trust propagation can lag a few seconds after CreateRole; retry AssumeRole
    itself (not any check assertion) until the freshly created role is assumable."""
    last_exc = None
    for _ in range(attempts):
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _access_denied_retry(fn, attempts=10, delay_s=3.0):
    """Retry an unexpected AccessDeniedException on a call the check expects to SUCCEED --
    never on one it expects to fail -- to absorb identity-policy propagation lag."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A role whose kms:Decrypt is conditioned on kms:EncryptionContext:PARAMETER_ARN decrypts
    only the named SecureString; a second one under the same key is denied, with the exact KMS
    denial message when kms:Decrypt is called directly.
    """

    ssm = ctx.client("ssm")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account

    def _param_name(suffix=""):
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }
    key = kms.create_key(
        Description="sim2real-behav ssm encryption-context-condition cmk",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    allowed_name = _track_parameter(_param_name("ctxcond-allowed-"))
    denied_name = _track_parameter(_param_name("ctxcond-denied-"))
    ssm.put_parameter(Name=allowed_name, Value="sim2real-allowed-plaintext", Type="SecureString", KeyId=key_id,
                       Tags=[{"Key": "sim2real", "Value": CHECK}])
    ssm.put_parameter(Name=denied_name, Value="sim2real-denied-plaintext", Type="SecureString", KeyId=key_id,
                       Tags=[{"Key": "sim2real", "Value": CHECK}])
    allowed_arn = ssm.get_parameter(Name=allowed_name)["Parameter"]["ARN"]

    # SSM sends {"PARAMETER_ARN": <parameter ARN>} as the encryption context on its decrypts.
    role_name = ctx.unique_name("sim2real-behav-ssmctxcond-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
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

    policy_name = f"{role_name}-perms"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GetAnyParameter",
                        "Effect": "Allow",
                        "Action": "ssm:GetParameter*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "DecryptOnlyForTheAllowedParameter",
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:EncryptionContext:PARAMETER_ARN": allowed_arn
                            }
                        },
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    restricted = ctx.client(
        "ssm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    assumed_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    key_arn = key["KeyMetadata"]["Arn"]

    allowed_read = _access_denied_retry(
        lambda: restricted.get_parameter(Name=allowed_name, WithDecryption=True)
    )["Parameter"]
    assert allowed_read["Value"] == "sim2real-allowed-plaintext", (
        f"the parameter the condition names must decrypt, got {allowed_read!r}"
    )

    code, message = _error(
        lambda: restricted.get_parameter(Name=denied_name, WithDecryption=True)
    )
    assert code == "AccessDeniedException", (
        "a parameter whose ARN does not satisfy the EncryptionContext condition must be "
        f"refused decryption with AccessDeniedException; got {code!r}: {message!r}"
    )
    assert "kms" in message.lower(), (
        "the denial must implicate kms:Decrypt, not ssm:GetParameter (which is granted on "
        f"'*' for this role); message was {message!r}"
    )
    # message varies: SSM relays KMS's text, which embeds the request id of SSM's OWN KMS
    # call, so this leg asserts the relayed denial's stable substring; the direct kms:Decrypt
    # call just below makes the identical denial with no relay, and there it is asserted exact.
    relayed_denial = (
        f"User: {assumed_arn} is not authorized to perform: kms:Decrypt on resource: "
        f"{key_arn} because no identity-based policy allows the kms:Decrypt action"
    )
    assert relayed_denial in message, (
        f"expected the relayed KMS denial {relayed_denial!r} within {message!r}"
    )

    # Called directly against KMS the same denial carries no per-call request id.
    denied_kms = ctx.client(
        "kms",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    denied_blob = base64.b64decode(
        ssm.get_parameter(Name=denied_name, WithDecryption=False)["Parameter"]["Value"]
    )
    denied_arn = ssm.get_parameter(Name=denied_name)["Parameter"]["ARN"]
    direct_code, direct_message = _error(
        lambda: denied_kms.decrypt(
            CiphertextBlob=denied_blob, EncryptionContext={"PARAMETER_ARN": denied_arn}
        )
    )
    assert (direct_code, direct_message) == ("AccessDeniedException", relayed_denial), (
        "the same role calling kms:Decrypt directly on the same ciphertext must be refused "
        f"with the identical, exact message (no relay suffix); got {(direct_code, direct_message)!r}"
    )

    # The condition binds kms:Decrypt, not ssm:GetParameter: both undecrypted reads succeed.
    for name, plaintext in (
        (allowed_name, "sim2real-allowed-plaintext"),
        (denied_name, "sim2real-denied-plaintext"),
    ):
        raw = restricted.get_parameter(Name=name, WithDecryption=False)["Parameter"]["Value"]
        assert raw != plaintext, (
            f"WithDecryption=False on {name!r} must not return the plaintext, got {raw!r}"
        )

    # Control: unconditional credentials decrypt both, so the denial is the role's condition.
    for name, plaintext in (
        (allowed_name, "sim2real-allowed-plaintext"),
        (denied_name, "sim2real-denied-plaintext"),
    ):
        admin_value = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
        assert admin_value == plaintext, (
            f"the admin's own decrypted read of {name!r} must return {plaintext!r}, got "
            f"{admin_value!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
