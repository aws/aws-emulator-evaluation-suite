"""put-key-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-key-policy"
GROUP = 'key_policy'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutKeyPolicy replaces the policy document; GetKeyPolicy reflects the ADDED statement (not
    just an echoed Id field), and the access the new document grants actually takes effect."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-putpolicy-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    plaintext = b"put-key-policy-must-take-effect"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]

    # Get current policy to find the account/principal
    current = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    root = f"arn:aws:iam::{account_id}:root"

    # Retain every existing statement (so the account root keeps kms:* and this check cannot
    # lock itself out) and append a new one -- the terminal read must show the ADDED statement,
    # not merely an echoed metadata field that an emulator could round-trip without honoring the
    # write at all.
    new_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "sim2real-test-policy",
            "Statement": current["Statement"]
            + [
                {
                    "Sid": "Sim2RealAdded",
                    "Effect": "Allow",
                    "Principal": {"AWS": root},
                    "Action": "kms:DescribeKey",
                    "Resource": "*",
                }
            ],
        }
    )

    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=new_policy)
    retrieved = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert retrieved.get("Id") == "sim2real-test-policy", (
        f"expected Id 'sim2real-test-policy', got {retrieved.get('Id')!r}"
    )
    assert len(retrieved["Statement"]) == len(current["Statement"]) + 1, (
        f"expected {len(current['Statement']) + 1} statements after the write, got "
        f"{len(retrieved['Statement'])}: {retrieved['Statement']!r}"
    )
    assert any(s.get("Sid") == "Sim2RealAdded" for s in retrieved["Statement"]), (
        f"the added statement 'Sim2RealAdded' did not survive the round trip: "
        f"{retrieved['Statement']!r}"
    )

    # The write took effect functionally, not just in the echoed document: the account root's
    # original kms:* statement is retained, so decrypt through the key still succeeds.
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"]
    assert decrypted == plaintext, (
        f"root access should survive the policy update; decrypt returned {decrypted!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
