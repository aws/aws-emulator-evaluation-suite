"""set-token-vault-cmk-concurrent-modification."""
from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-token-vault-cmk-concurrent-modification"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent SetTokenVaultCMK calls on the singleton token vault are serialized: a
    rejected writer fails with a stale-write rejection, never a silent lost update, and the
    vault ends on exactly one of the two submitted CMK configurations."""
    bac = ctx.client("bedrock-agentcore-control")
    kms = ctx.client("kms")

    # Defensively reset the vault to an AWS owned key first. A prior interrupted test run
    # can leave the vault pointing at a customer key that's since been scheduled for KMS
    # deletion; SetTokenVaultCMK validates the *old* key on every call, so that leftover
    # state must be repaired before this check's own keys can be exercised.
    _reset_vault_to_owned_key(bac, kms)

    key_a = kms.create_key(
        Description=ctx.unique_name("sim2real-bac-tv-a-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "bedrock-agentcore-control-behavioral"}],
    )["KeyMetadata"]["KeyId"]
    key_b = kms.create_key(
        Description=ctx.unique_name("sim2real-bac-tv-b-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "bedrock-agentcore-control-behavioral"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_b, PendingWindowInDays=7))
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_a, PendingWindowInDays=7))
    # Registered after the key deletions so it runs before them: SetTokenVaultCMK validates the
    # vault's current key, which must not yet be pending deletion.
    ctx.on_cleanup(lambda: _reset_vault_to_owned_key(bac, kms))
    key_arn_a = kms.describe_key(KeyId=key_a)["KeyMetadata"]["Arn"]
    key_arn_b = kms.describe_key(KeyId=key_b)["KeyMetadata"]["Arn"]
    _grant_token_vault_key_policy(kms, key_a)
    _grant_token_vault_key_policy(kms, key_b)

    # Warm up key-policy propagation with a throwaway call before racing -- otherwise the
    # race below observes transient permission-propagation ValidationExceptions instead of
    # the actual concurrency behavior under test.
    _set_cmk_with_retry(bac, key_arn_a)
    _set_cmk_with_retry(bac, key_arn_b)

    def _setter(arn):
        return lambda: bac.set_token_vault_cmk(
            kmsConfiguration={"keyType": "CustomerManagedKey", "kmsKeyArn": arn}
        )

    results = _race([_setter(key_arn_a), _setter(key_arn_b)])
    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]
    # The vault was already left on key_arn_b by the warm-up above, so an assertion on the
    # final key alone cannot tell "the race produced a real write" from "both racers were
    # spuriously rejected and the pre-race warm-up state simply persisted". Requiring at
    # least one success during the race itself closes that gap.
    assert len(successes) >= 1, f"expected at least one of the two racers to succeed, got {results}"
    # AWS may accept both writers and serialize them server-side, or refuse the one that
    # arrives while the other's mutation is in flight; each outcome is graded exactly.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    vault_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:token-vault/default"
    expected = f"The tenant encryption key mutation operation for {vault_arn} is already in progress."
    for _, (code, message) in failures:
        assert code == "ValidationException", (
            f"expected the loser to be refused with ValidationException, got {code!r} (full: {results})"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    final_arn = bac.get_token_vault()["kmsConfiguration"]["kmsKeyArn"]
    if len(successes) == 1:
        winner_arn = key_arn_a if results[0][0] else key_arn_b
        assert final_arn == winner_arn, f"expected the vault on the sole winner {winner_arn}, got {final_arn}"
    else:
        assert final_arn in (key_arn_a, key_arn_b), f"vault CMK left in inconsistent state: {final_arn}"


# ===== helpers =====
def _reset_vault_to_owned_key(bac, kms, timeout_s=60.0, interval_s=5.0):
    """Best-effort reset of the token vault to the AWS owned key, repairing the leftover
    "old key" state a prior interrupted run can leave behind (a customer key that's since
    been scheduled for KMS deletion, which SetTokenVaultCMK still validates on every call)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            bac.set_token_vault_cmk(kmsConfiguration={"keyType": "ServiceManagedKey"})
            return
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            match = re.search(r"KMS [Kk]ey (arn:aws:kms:\S+)", msg)
            if match:
                key_arn = match.group(1)
                # KMSInvalidStateException: the key is not in a state this repair applies to.
                for repair in (kms.cancel_key_deletion, kms.enable_key):
                    try:
                        repair(KeyId=key_arn)
                    except ClientError as repair_exc:
                        if repair_exc.response["Error"]["Code"] not in (
                            "KMSInvalidStateException",
                            "NotFoundException",
                        ):
                            raise
                time.sleep(interval_s)
                continue
            if exc.response["Error"]["Code"] == "ValidationException":
                time.sleep(interval_s)
                continue
            raise
    # last attempt, let any exception propagate as a real failure
    bac.set_token_vault_cmk(kmsConfiguration={"keyType": "ServiceManagedKey"})


def _grant_token_vault_key_policy(kms, key_id):
    """AgentCore Identity requires the token vault's customer managed key to explicitly
    grant the bedrock-agentcore-identity service permission to use it, scoped to the
    default token vault via an encryption-context ARN condition."""
    current = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    current["Statement"].append(
        {
            "Sid": "BedrockAgentCoreIdentityKMSAccess",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext"],
            "Resource": "*",
            "Condition": {
                "StringLike": {"kms:ViaService": "bedrock-agentcore-identity.*.amazonaws.com"},
                "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"},
                "ArnLike": {
                    "kms:EncryptionContext:aws-crypto-ec:aws:bedrock-agentcore-identity:token-vault-arn": (
                        "arn:aws:bedrock-agentcore:*:*:token-vault/default"
                    )
                },
            },
        }
    )
    current["Statement"].append(
        {
            "Sid": "BedrockAgentCoreIdentityDescribeKeyKMSAccess",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["kms:DescribeKey"],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"},
                "StringLike": {"kms:ViaService": "bedrock-agentcore-identity.*.amazonaws.com"},
            },
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(current))


def _set_cmk_with_retry(bac, kms_key_arn, timeout_s=120.0, interval_s=5.0):
    """SetTokenVaultCMK validates KMS key policy/permissions synchronously; a key policy
    statement added moments ago can still fail that check while KMS propagates it."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bac.set_token_vault_cmk(kmsConfiguration={"keyType": "CustomerManagedKey", "kmsKeyArn": kms_key_arn})
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _race(fns, timeout_s=60.0):
    """Fire every fn as close to simultaneously as possible; return [(ok, value_or_code), ...]."""
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            return i, False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
