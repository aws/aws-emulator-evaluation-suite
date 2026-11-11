"""update-alias."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-alias"
GROUP = 'aliases'
SERVICES = ['kms']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAlias re-targets an alias to a different key."""
    kms = ctx.client("kms")
    key1 = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key1: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    key2 = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key2: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    alias_name = f"alias/sim2real-behav-{uuid.uuid4().hex[:8]}"
    kms.create_alias(AliasName=alias_name, TargetKeyId=key1)
    ctx.on_cleanup(lambda _a=alias_name: kms.delete_alias(AliasName=_a))
    # KMS aliases are eventually consistent: poll until the new alias resolves.
    _deadline = time.monotonic() + 15
    while time.monotonic() < _deadline:
        try:
            kms.describe_key(KeyId=alias_name)
            break
        except ClientError:
            time.sleep(0.5)

    kms.update_alias(AliasName=alias_name, TargetKeyId=key2)
    meta = _poll_until(
        lambda: kms.describe_key(KeyId=alias_name)["KeyMetadata"],
        lambda m: m["KeyId"] == key2,
        timeout_s=15,
        interval_s=1.0,
        description="UpdateAlias propagation",
    )
    assert meta["KeyId"] == key2, (
        f"expected {alias_name} to resolve to {key2!r} via DescribeKey after UpdateAlias, "
        f"got {meta['KeyId']!r}"
    )

    # Independent read via a different operation than DescribeKey: ListAliases must agree —
    # the alias now appears under key2's aliases and no longer under key1's.
    aliases_for_key2 = _poll_until(
        lambda: {a["AliasName"] for a in kms.list_aliases(KeyId=key2)["Aliases"]},
        lambda names: alias_name in names,
        timeout_s=15,
        interval_s=1.0,
        description="alias to appear under key2 in ListAliases",
    )
    assert alias_name in aliases_for_key2, (
        f"expected {alias_name} in ListAliases(KeyId={key2!r}), got {aliases_for_key2!r}"
    )
    aliases_for_key1 = {a["AliasName"] for a in kms.list_aliases(KeyId=key1)["Aliases"]}
    assert alias_name not in aliases_for_key1, (
        f"expected {alias_name} to no longer list under the old key {key1!r} after retarget, "
        f"but ListAliases(KeyId={key1!r}) still returned {aliases_for_key1!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
