"""delete-alias."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-alias"
GROUP = 'aliases'
SERVICES = ['kms']

ERR_NOT_FOUND = "NotFoundException"

def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _resolves(kms, alias_name):
    """True when DescribeKey resolves the alias, False when KMS reports it not found."""
    try:
        kms.describe_key(KeyId=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == ERR_NOT_FOUND:
            return False
        raise
    return True

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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlias removes the alias: DescribeKey via the alias fails, a mutation
    (UpdateAlias) on the dead name also fails, and the name is reusable afterward."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-delete-alias"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    alias_name = f"alias/sim2real-behav-{uuid.uuid4().hex[:8]}"

    def _wait_resolves():
        # KMS aliases are eventually consistent — poll until resolvable.
        _poll_until(
            lambda: _resolves(kms, alias_name),
            lambda resolved: resolved,
            timeout_s=15,
            interval_s=0.5,
            description="alias resolution",
        )

    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=alias_name: kms.delete_alias(AliasName=_a))
    _wait_resolves()

    kms.delete_alias(AliasName=alias_name)

    # Alias deletion is eventually consistent — a DescribeKey via the alias can
    # still resolve for a short window after DeleteAlias returns. Poll until the
    # alias no longer resolves.
    _poll_until(
        lambda: _resolves(kms, alias_name),
        lambda resolved: not resolved,
        timeout_s=15,
        interval_s=1.0,
        description="DeleteAlias propagation",
    )
    region = kms.meta.region_name
    expected_missing = (
        ERR_NOT_FOUND,
        f"Alias arn:aws:kms:{region}:{ctx.account}:{alias_name} is not found.",
    )
    refused = _error(lambda: kms.describe_key(KeyId=alias_name))
    assert refused == expected_missing, f"Expected {expected_missing!r}, got {refused!r}"

    # A delete must also block a mutation on the dead identifier, not just a read.
    update_refused = _error(lambda: kms.update_alias(AliasName=alias_name, TargetKeyId=key_id))
    assert update_refused == expected_missing, (
        f"Expected UpdateAlias on a deleted alias to fail with {expected_missing!r}, got {update_refused!r}"
    )

    # The identifier is reusable: recreating it under the same name succeeds and
    # resolves again (cleanup above already targets this name).
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    _wait_resolves()

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
