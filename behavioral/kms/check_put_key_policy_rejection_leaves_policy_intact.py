"""put-key-policy-rejection-leaves-policy-intact."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "put-key-policy-rejection-leaves-policy-intact"
GROUP = 'key_policy'
SERVICES = ['kms']

ERR_MALFORMED = "MalformedPolicyDocumentException"
ERR_VALIDATION = "ValidationException"
MSG_INVALID_PRINCIPALS = "Policy contains a statement with one or more invalid principals."
MSG_INVALID_POLICY_NAME = "Invalid policy name"



def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_root_arn(key_arn: str) -> str:
    """Derive the account root principal ARN from a key ARN without calling STS."""
    return f"arn:aws:iam::{key_arn.split(':')[4]}:root"


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window; bills until then)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


def _restore_policy(kms, key_arn: str, policy: str) -> None:
    """Put back the policy document captured before this check modified it."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=policy)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Every rejected PutKeyPolicy leaves the stored document unchanged and the key working, and
    only the name `default` is a valid key-policy name.
    """
    # Every negative is a rejected policy that keeps the root kms:* statement, so no lockout.
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-polrej-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": "put-key-policy-rejection-leaves-policy-intact"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    original = kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"]
    original_doc = json.loads(original)
    ctx.on_cleanup(lambda _a=key_arn, _p=original: _restore_policy(kms, _a, _p))
    root = _account_root_arn(key_arn)

    plaintext = b"policy-rejection-must-be-atomic"
    ct = kms.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]

    def _assert_policy_unchanged(label: str) -> None:
        now = json.loads(kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"])
        assert now == original_doc, (
            f"a rejected PutKeyPolicy ({label}) must leave the document unchanged; "
            f"got {now!r}"
        )

    # Case 1: the document is not JSON.
    code, msg = _err(lambda: kms.put_key_policy(
        KeyId=key_arn, PolicyName="default", Policy="{not json"))
    assert code == ERR_MALFORMED, f"malformed JSON must raise {ERR_MALFORMED}, got {code!r}"
    assert msg == "", f"AWS sends this refusal with no message text, got {msg!r}"
    _assert_policy_unchanged("malformed JSON")

    # Case 2: valid JSON naming a principal that does not exist; KMS resolves principals at write
    # time.
    ghost = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": root},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "Ghost", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{key_arn.split(':')[4]}:role/"
                                  f"sim2real-behav-kms-no-such-role"},
             "Action": "kms:Decrypt", "Resource": "*"},
        ],
    }
    code, ghost_msg = _err(lambda: kms.put_key_policy(
        KeyId=key_arn, PolicyName="default", Policy=json.dumps(ghost)))
    assert code == ERR_MALFORMED, (
        f"a policy naming a nonexistent IAM role must raise {ERR_MALFORMED}, got {code!r}"
    )
    # Same error code as case 1, but only principal resolution carries message text.
    assert ghost_msg == MSG_INVALID_PRINCIPALS, (
        f"the refusal must say the principals are invalid, not merely that the document is "
        f"malformed (that is how principal resolution is told apart from bad syntax): "
        f"{ghost_msg!r}"
    )
    _assert_policy_unchanged("nonexistent principal")

    # Case 3: valid JSON but structurally invalid (an empty Statement list).
    code, msg = _err(lambda: kms.put_key_policy(
        KeyId=key_arn, PolicyName="default",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": []})))
    assert code == ERR_MALFORMED, (
        f"an empty Statement list must raise {ERR_MALFORMED}, got {code!r}"
    )
    assert msg == "", f"AWS sends this refusal with no message text, got {msg!r}"
    _assert_policy_unchanged("empty Statement")

    # Case 4: a valid document under an unsupported policy name. PolicyNameType permits [\w]+ so
    # botocore forwards it; KMS rejects it as a bad parameter (ValidationException), and
    # GetKeyPolicy does the same rather than NotFoundException.
    valid_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": root},
             "Action": "kms:*", "Resource": "*"},
        ],
    })
    code, put_msg = _err(lambda: kms.put_key_policy(
        KeyId=key_arn, PolicyName="notdefault", Policy=valid_doc))
    assert code == ERR_VALIDATION, (
        f"PolicyName='notdefault' must raise {ERR_VALIDATION} (KMS rejects the name as a bad "
        f"parameter, not as an unsupported operation), got {code!r}"
    )
    assert put_msg == MSG_INVALID_POLICY_NAME, (
        f"the refusal must name the offending parameter ({MSG_INVALID_POLICY_NAME!r}): "
        f"{put_msg!r}"
    )
    _assert_policy_unchanged("non-default policy name")
    assert kms.list_key_policies(KeyId=key_arn)["PolicyNames"] == ["default"], (
        kms.list_key_policies(KeyId=key_arn)["PolicyNames"]
    )
    # A rejected write must not have created the name either -- and the read is refused the same
    # way the write was, by name validation rather than by a lookup miss.
    get_code, get_msg = _err(lambda: kms.get_key_policy(KeyId=key_arn, PolicyName="notdefault"))
    assert get_code == ERR_VALIDATION, (
        f"GetKeyPolicy(PolicyName='notdefault') must raise {ERR_VALIDATION}, not a lookup miss, "
        f"got {get_code!r}"
    )
    assert get_msg == MSG_INVALID_POLICY_NAME, get_msg

    decrypted = kms.decrypt(CiphertextBlob=ct, KeyId=key_arn)["Plaintext"]
    assert decrypted == plaintext, (
        f"the key must still decrypt after four rejected PutKeyPolicy calls; got {decrypted!r}"
    )
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"the key must remain Enabled after four rejections, got {state!r}"

    # Compared structurally: KMS re-serialises the document (whitespace and key order vary).
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=valid_doc)
    stored = json.loads(kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"])
    assert stored == json.loads(valid_doc), stored
    assert kms.decrypt(CiphertextBlob=ct, KeyId=key_arn)["Plaintext"] == plaintext, (
        "the account root retains kms:* under the replacement policy"
    )
    # Restore explicitly as well as in teardown, so a later assertion failure cannot leave the
    # narrowed policy in place.
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=original)
    _assert_policy_unchanged("explicit restore")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
