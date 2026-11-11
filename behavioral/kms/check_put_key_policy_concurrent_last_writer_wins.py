"""put-key-policy-concurrent-last-writer-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "put-key-policy-concurrent-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutKeyPolicy calls on one key succeed and leave exactly one of the two
    written documents (commit order is undocumented), and two sequential puts leave the later
    one: the last write wins rather than a merge, an error or a stale document."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmspolicy-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    def _policy(marker: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "EnableIAMUserPermissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": f"ConcurrencyMarker{marker}",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:DescribeKey",
                        "Resource": "*",
                    },
                ],
            }
        )

    policy_a = _policy("A")
    policy_b = _policy("B")

    def _put(policy: str) -> None:
        kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)

    def _get_until(wanted: list[str]) -> str:
        # PutKeyPolicy is documented eventually consistent, so poll briefly for a written one.
        targets = [json.loads(p) for p in wanted]
        policy = None
        for _ in range(15):
            policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            if json.loads(policy) in targets:
                break
            time.sleep(0.5)
        return policy

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_put, policy_a)
        fut_b = pool.submit(_put, policy_b)
        fut_a.result()  # raises if PutKeyPolicy errored -> no lock-conflict tolerated
        fut_b.result()

    # Client completion order does not show server commit order, so either document may win.
    final_policy = _get_until([policy_a, policy_b])
    assert json.loads(final_policy) in (json.loads(policy_a), json.loads(policy_b)), (
        f"expected one of the two concurrently written policies to win, "
        f"but GetKeyPolicy returned a different policy: {final_policy}"
    )

    # Sequential writes have a defined order, so the later one must win. The later one is the
    # race's loser, so a write that is dropped or not applied leaves the race's winner instead.
    if json.loads(final_policy) == json.loads(policy_a):
        first, second, second_marker = policy_a, policy_b, "B"
    else:
        first, second, second_marker = policy_b, policy_a, "A"
    _put(first)
    _put(second)
    final_policy = _get_until([second])
    assert json.loads(final_policy) == json.loads(second), (
        f"expected the later sequential PutKeyPolicy (marker={second_marker}) to win, "
        f"but GetKeyPolicy returned: {final_policy}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
