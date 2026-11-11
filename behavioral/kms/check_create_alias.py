"""create-alias."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-alias"
GROUP = 'aliases'
SERVICES = ['kms']

ERR_NOT_FOUND = "NotFoundException"
MSG_ALIAS_NOT_FOUND = "Alias {alias_arn} is not found."

def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _delete_alias_if_present(kms, alias: str) -> None:
    """Teardown: the check deletes the alias itself, so NotFound here is benign."""
    try:
        kms.delete_alias(AliasName=alias)
    except kms.exceptions.NotFoundException:
        pass

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
    """CreateAlias succeeds and the alias is resolvable via DescribeKey; DeleteAlias then
    makes the same read fail with the specific not-found code."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-create-alias"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    alias_name = f"alias/sim2real-behav-test-{uuid.uuid4().hex[:8]}"
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=alias_name: _delete_alias_if_present(kms, _a))
    # Alias resolution is eventually consistent on real AWS — a DescribeKey
    # issued immediately after CreateAlias can still raise NotFoundException.
    # Poll (swallowing the transient NotFound) until the alias resolves.
    def _resolve():
        try:
            return kms.describe_key(KeyId=alias_name)["KeyMetadata"]
        except kms.exceptions.NotFoundException:
            return None

    meta = _poll_until(
        _resolve,
        lambda m: m is not None and m.get("KeyId") == key_id,
        timeout_s=15,
        interval_s=1.0,
        description="CreateAlias propagation",
    )
    assert meta["KeyId"] == key_id, f"expected alias {alias_name!r} to resolve to {key_id!r}, got {meta.get('KeyId')!r}"

    # The check already deletes this alias in cleanup; prove the delete is
    # real instead of leaving it unasserted — DescribeKey via the alias
    # must fail with the specific not-found code once DeleteAlias propagates.
    kms.delete_alias(AliasName=alias_name)
    _poll_until(
        _resolve,
        lambda m: m is None,
        timeout_s=15,
        interval_s=1.0,
        description="DeleteAlias propagation",
    )
    alias_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:{alias_name}"
    got = _err(lambda: kms.describe_key(KeyId=alias_name))
    expected = (ERR_NOT_FOUND, MSG_ALIAS_NOT_FOUND.format(alias_arn=alias_arn))
    assert got == expected, f"expected {expected!r} after DeleteAlias, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
