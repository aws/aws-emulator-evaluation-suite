"""error-duplicate-alias."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-duplicate-alias"
GROUP = 'errors'
SERVICES = ['kms']

ERR_ALREADY_EXISTS = "AlreadyExistsException"

def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError; an
    unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

def _poll_until(probe, predicate, *, timeout_s=30, interval_s=0.5, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            last = exc
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias with an existing alias name raises AlreadyExistsException, the alias keeps
    resolving to the original key (the failed create has no effect), and once the name is freed
    the identical call succeeds."""
    kms = ctx.client("kms")
    key1_meta = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]
    key1 = key1_meta["KeyId"]
    ctx.on_cleanup(lambda _k=key1: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    key2 = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key2: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    alias_name = f"alias/sim2real-behav-{uuid.uuid4().hex[:8]}"

    # positive control: the first bind of a fresh alias name succeeds.
    kms.create_alias(AliasName=alias_name, TargetKeyId=key1)
    ctx.on_cleanup(lambda _a=alias_name: kms.delete_alias(AliasName=_a))
    # KMS aliases are eventually consistent — poll until the first alias resolves before
    # attempting the duplicate create. Only the first create is expected to succeed; the
    # second create below is the deliberately-failing one.
    _poll_until(
        lambda: kms.describe_key(KeyId=alias_name)["KeyMetadata"]["KeyId"],
        lambda kid: kid == key1,
        description="alias resolves to key1",
    )

    # break exactly one thing: bind the same name to a different key.
    code, message = _error(lambda: kms.create_alias(AliasName=alias_name, TargetKeyId=key2))
    assert code == ERR_ALREADY_EXISTS, f"Expected {ERR_ALREADY_EXISTS}, got {code!r}"
    assert message == (
        f"An alias with the name {key1_meta['Arn'].split(':key/')[0]}:{alias_name} already exists"
    ), f"unexpected message {message!r}"

    # effect-absent: the failed create did not move the alias off key1.
    resolved = kms.describe_key(KeyId=alias_name)["KeyMetadata"]["KeyId"]
    assert resolved == key1, f"alias should still resolve to key1 after the rejected create, got {resolved!r}"

    # restore: free the name, then the identical call now succeeds.
    kms.delete_alias(AliasName=alias_name)
    _poll_until(
        lambda: kms.describe_key(KeyId=alias_name),
        lambda last: isinstance(last, ClientError)
        and last.response.get("Error", {}).get("Code") == "NotFoundException",
        description="alias becomes unresolvable after delete",
    )
    kms.create_alias(AliasName=alias_name, TargetKeyId=key2)
    rebound = _poll_until(
        lambda: kms.describe_key(KeyId=alias_name)["KeyMetadata"]["KeyId"],
        lambda kid: kid == key2,
        description="alias resolves to key2 after the name is freed",
    )
    assert rebound == key2, f"alias should resolve to key2 once freed and recreated, got {rebound!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
