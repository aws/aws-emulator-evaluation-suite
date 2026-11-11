"""create-grant-dry-run-no-op."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-grant-dry-run-no-op"
GROUP = "error-semantics"
SERVICES = ["kms"]
MSG_DRY_RUN = "The request would have succeeded, but the DryRun option is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGrant with DryRun=True returns DryRunOperationException and creates no grant."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    key_id = _create_symmetric_key(ctx)
    account_id = sts.get_caller_identity()["Account"]
    grantee = f"arn:aws:iam::{account_id}:root"

    code = _err(
        lambda: kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=grantee,
            Operations=["Decrypt"],
            DryRun=True,
        )
    )
    assert code == ("DryRunOperationException", MSG_DRY_RUN), (
        f"expected DryRunOperationException {MSG_DRY_RUN!r}, got {code!r}"
    )

    grants_after_dry_run = kms.list_grants(KeyId=key_id)["Grants"]
    assert grants_after_dry_run == [], "DryRun=True must not create a grant"

    # positive control: the identical call without DryRun succeeds and becomes visible
    created = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee,
        Operations=["Decrypt"],
    )
    grant_id = created["GrantId"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    _poll_until(
        lambda: {g["GrantId"] for g in kms.list_grants(KeyId=key_id)["Grants"]},
        lambda ids: grant_id in ids,
        timeout_s=60.0,
        interval_s=3.0,
    )


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _create_symmetric_key(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    return key_id


def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
