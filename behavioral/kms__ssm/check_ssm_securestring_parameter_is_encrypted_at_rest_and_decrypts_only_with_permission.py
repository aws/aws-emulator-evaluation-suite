"""ssm-securestring-parameter-is-encrypted-at-rest-and-decrypts-only-with-permission."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-securestring-parameter-is-encrypted-at-rest-and-decrypts-only-with-permission"
GROUP = 'parameter-store'
SERVICES = ['kms', 'ssm']

_PLAINTEXT = "sim2real-behav-securestring-plaintext-a7f3"


# What _error reports for a call that SUCCEEDED: a value no error code can equal.
_ACCEPTED = "<call succeeded>"


def _error(fn):
    """Return (code, message) from the ClientError fn raises, or (_ACCEPTED, "") on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    return _ACCEPTED, ""


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _call_with_retry(fn, codes, retries=15, delay=2.0):
    """Bounded retry over `codes` for IAM/KMS eventual consistency, which has nothing to poll."""
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s=90, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _describe_one(ssm, name):
    """Every version record for `name` from GetParameterHistory, fully paginated."""
    return (
        ssm.get_paginator("get_parameter_history")
        .paginate(Name=name)
        .build_full_result()["Parameters"]
    )


def _target_client(ctx, service, key, secret, token):
    """A client for `service` against the same target as ctx.client(service), signing with the
    (key, secret, token) triple."""
    return ctx.client(service, creds={
        "aws_access_key_id": key,
        "aws_secret_access_key": secret,
        "aws_session_token": token,
    })


def _delete_role(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_assumable_role(ctx, iam, account_id, permission_policy):
    """An IAM role trusted by this account's root with an inline permission policy."""
    role_name = ctx.unique_name("sim2real-behav-ssm-nokms-")
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
    policy_name = f"{role_name}-perms"
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav securestring kms-denial probe",
        Tags=[{"Key": "sim2real", "Value": "securestring-kms-denial"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permission_policy),
    )
    return resp["Role"]["Arn"]


def _assume_role_client(ctx, role_arn, service, max_attempts=20):
    """AssumeRole (retrying while IAM propagates) and return a `service` client from the
    temporary credentials, after verifying them with a throwaway GetCallerIdentity."""
    sts = ctx.client("sts")
    creds = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sess-")[:64]
            )["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if creds is None:
        assert last_exc is not None
        raise last_exc
    triple = (creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
    probe = _target_client(ctx, "sts", *triple)
    identity = None
    for _ in range(max_attempts):
        try:
            identity = probe.get_caller_identity()
            break
        except ClientError:
            time.sleep(2)
    assert identity is not None, f"the assumed-role credentials for {role_arn!r} never became usable"
    return _target_client(ctx, service, *triple), identity, triple


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c7",
)
def run(ctx) -> None:
    """A SecureString's WithDecryption=False value is a real KMS ciphertext of the plaintext; a
    same-account role the key policy denies kms:Decrypt is refused the plaintext but reads the same
    ciphertext, and removing the Deny lets it decrypt.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-securestring.html
    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html
    """

    ssm = ctx.client("ssm")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # The role's IAM policy grants kms:Decrypt on everything, so only the key policy can refuse it.
    role_arn = _create_assumable_role(
        ctx,
        iam,
        account_id,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:DescribeParameters",
                        "kms:Decrypt",
                    ],
                    "Resource": "*",
                }
            ],
        },
    )

    # --- a customer-managed key that denies kms:Decrypt to exactly that role --
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "DenyDecryptToProbeRole",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
        ],
    }
    # A role ARN is not immediately resolvable inside a key policy.
    key = _call_with_retry(
        lambda: kms.create_key(
            Description="sim2real-behav ssm securestring cmk",
            KeyUsage="ENCRYPT_DECRYPT",
            Policy=json.dumps(key_policy),
            Tags=[{"TagKey": "sim2real", "TagValue": "securestring-kms-denial"}],
        ),
        codes=("MalformedPolicyDocumentException",),
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    # A CMK can only be SCHEDULED for deletion; 7 days is the minimum window.
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    # --- the SecureString parameter ------------------------------------------
    name = _param_name(ctx, "secure-")
    _track_parameter(ctx, ssm, name)
    ssm.put_parameter(
        Name=name,
        Value=_PLAINTEXT,
        Type="SecureString",
        KeyId=key_id,
        Tags=[{"Key": "sim2real", "Value": "securestring-kms-denial"}],
    )

    described = ssm.get_parameter(Name=name)["Parameter"]
    assert described["Type"] == "SecureString", described
    # GetParameterHistory is read-your-writes and reports the KeyId; DescribeParameters with a
    # Name/Equals filter can still return [] after 90 s.
    metadata = _describe_one(ssm, name)
    assert len(metadata) == 1, (
        f"GetParameterHistory must hold exactly one version of {name!r}, got {metadata!r}"
    )
    assert metadata[0]["Type"] == "SecureString", metadata[0]
    assert metadata[0].get("KeyId") in (key_id, key_arn), (
        "the parameter must record the customer-managed key it was encrypted under; got "
        f"{metadata[0].get('KeyId')!r}, expected {key_id!r} or {key_arn!r}"
    )

    # --- the two read forms differ, and the undecrypted one is real ciphertext -
    raw = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]["Value"]
    assert raw != _PLAINTEXT, (
        f"WithDecryption=False returned the plaintext {raw!r}; the value is labelled "
        "SecureString but is not encrypted"
    )
    decrypted = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    assert decrypted == _PLAINTEXT, (
        f"WithDecryption=True returned {decrypted!r}, expected {_PLAINTEXT!r}"
    )

    # KMS must decrypt those exact bytes and attribute them to the parameter's key. SSM binds
    # the ciphertext to the encryption context {"PARAMETER_ARN": <arn>}.
    blob = base64.b64decode(raw)
    parameter_arn = described["ARN"]
    encryption_context = {"PARAMETER_ARN": parameter_arn}
    # KMS sends this refusal with no message text; botocore reports the absent text as "".
    unbound = _error(lambda: kms.decrypt(CiphertextBlob=blob))
    assert unbound == ("InvalidCiphertextException", ""), (
        "the ciphertext must be bound to this parameter's ARN, so a Decrypt with no "
        f"EncryptionContext must be refused with InvalidCiphertextException; got {unbound!r}"
    )
    unwrapped = kms.decrypt(CiphertextBlob=blob, EncryptionContext=encryption_context)
    assert unwrapped["Plaintext"].decode() == _PLAINTEXT, (
        "the WithDecryption=False bytes must be a KMS ciphertext of the plaintext; KMS "
        f"decrypted them to {unwrapped['Plaintext']!r}"
    )
    assert unwrapped["KeyId"] == key_arn, (
        "KMS must attribute the ciphertext to the customer-managed key the parameter "
        f"names; got {unwrapped['KeyId']!r}, expected {key_arn!r}"
    )

    # --- break exactly one thing: assume the role the KEY POLICY denies -------
    denied_ssm, identity, denied_creds = _assume_role_client(ctx, role_arn, "ssm")
    assert identity["Account"] == account_id, (
        "the assumed-role session must be in the same account as the parameter; got "
        f"{identity!r}"
    )
    assert identity["Arn"] != ctx.client("sts").get_caller_identity()["Arn"], (
        "the denied read must be made by a DIFFERENT principal than the writer, else the "
        f"denial proves nothing; both were {identity['Arn']!r}"
    )

    code, message = _error(
        lambda: denied_ssm.get_parameter(Name=name, WithDecryption=True)
    )
    # message varies: SSM relays KMS's text, which embeds the request id of SSM's own KMS call;
    # its stable part, the KMS denial naming this principal, action and key, is asserted here and
    # the direct kms:Decrypt below asserts the exact KMS message for the same denial.
    assert code == "AccessDeniedException", (
        "a principal the key policy denies kms:Decrypt must be refused the plaintext with "
        f"AccessDeniedException; got {code!r}: {message!r}"
    )
    assert "kms" in message.lower(), (
        "the denial must implicate KMS rather than the parameter: the role's own IAM "
        f"policy allows ssm:GetParameter; message was {message!r}"
    )
    relayed_denial = (
        f"User: {identity['Arn']} is not authorized to perform: kms:Decrypt on resource: "
        f"{key_arn} with an explicit deny in a resource-based policy"
    )
    assert relayed_denial in message, (
        f"the relayed KMS denial must name this principal, kms:Decrypt and the key; expected "
        f"{relayed_denial!r} within {message!r}"
    )

    # Parameter Store is shared across every principal in an account, so this read must succeed.
    denied_view = denied_ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert denied_view["Value"] == raw, (
        "the same account's other principal must read byte-identical ciphertext; got "
        f"{denied_view['Value'][:32]!r}, expected {raw[:32]!r}"
    )
    assert denied_view["Version"] == described["Version"], (
        "the assumed-role session must see the same parameter version as the writer, not a "
        f"per-credential copy; got {denied_view['Version']!r} vs {described['Version']!r}"
    )
    assert denied_view["ARN"] == described["ARN"], (
        f"the parameter ARN must be identical across principals; got "
        f"{denied_view['ARN']!r} vs {described['ARN']!r}"
    )

    # A direct kms:Decrypt by the same role is refused too, locating the denial in the key policy.
    denied_kms = _target_client(ctx, "kms", *denied_creds)
    direct = _error(
        lambda: denied_kms.decrypt(
            CiphertextBlob=blob, EncryptionContext=encryption_context
        )
    )
    expected_kms_message = (
        f"User: {identity['Arn']} is not authorized to perform: kms:Decrypt on resource: "
        f"{key_arn} with an explicit deny in a resource-based policy"
    )
    assert direct == ("AccessDeniedException", expected_kms_message), (
        "the same role calling kms:Decrypt directly on the same ciphertext must also be "
        "refused, which is what locates the denial in the key policy; got "
        f"{direct!r}, expected ('AccessDeniedException', {expected_kms_message!r})"
    )

    # Removing the Deny must let the same call on the same role succeed.
    restored_policy = {
        "Version": "2012-10-17",
        "Statement": [key_policy["Statement"][0]],
    }
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(restored_policy))

    def _denied_read_code():
        return _error(
            lambda: denied_ssm.get_parameter(Name=name, WithDecryption=True)
        )

    restored_code, restored_message = _poll(
        _denied_read_code,
        lambda result: result[0] == _ACCEPTED,
        timeout_s=90,
        interval_s=3.0,
    )
    assert restored_code == _ACCEPTED, (
        "detaching the key-policy Deny must restore kms:Decrypt for the same role on the "
        f"identical call; got {restored_code!r}: {restored_message!r}"
    )
    restored_value = denied_ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    assert restored_value == _PLAINTEXT, (
        "after restoring the key policy, the previously-denied role must decrypt to the "
        f"original plaintext; got {restored_value!r}"
    )

    # --- final positive control: the writer can still decrypt ----------------
    assert (
        ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
        == _PLAINTEXT
    ), "the denial must not have disturbed the writer's own decrypted read"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
