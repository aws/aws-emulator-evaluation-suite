"""op-delete-nonexistent-alias-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-delete-nonexistent-alias-rejected"
GROUP = 'errors'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_alias_if_present(kms, alias_name):
    """Teardown: the check deletes the alias itself, so an already-gone alias is fine."""
    try:
        kms.delete_alias(AliasName=alias_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlias on a never-created alias fails with NotFoundException, while DeleteAlias on a
    real alias succeeds and the alias leaves ListAliases.
    """
    kms = ctx.client("kms")

    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-op-ghost-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    def _alias_names():
        return [a["AliasName"] for a in kms.list_aliases(KeyId=key_id).get("Aliases", [])]

    real_alias = ctx.unique_name("alias/sim2real-behav-op-ghost-real-")
    kms.create_alias(AliasName=real_alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=real_alias: _delete_alias_if_present(kms, _a))

    # Aliases are eventually consistent; DeleteAlias right after CreateAlias can 404.
    _poll_until(
        _alias_names,
        lambda names: real_alias in names,
        description="CreateAlias visibility",
    )

    kms.delete_alias(AliasName=real_alias)

    remaining = _poll_until(
        _alias_names,
        lambda names: real_alias not in names,
        description="DeleteAlias propagation",
    )
    assert real_alias not in remaining, f"{real_alias} still in ListAliases after DeleteAlias"

    ghost = f"alias/sim2real-behav-op-ghost-{uuid.uuid4().hex[:8]}"
    code, message = _error(lambda: kms.delete_alias(AliasName=ghost))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    arn_prefix = meta["Arn"].rsplit(":", 1)[0]  # arn:aws:kms:<region>:<account>
    assert message == f"Alias {arn_prefix}:{ghost} is not found.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
