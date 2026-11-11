"""create-grant-dry-run-no-effect."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-grant-dry-run-no-effect"
GROUP = "error-semantics"
SERVICES = ["kms"]
MSG_DRY_RUN = "The request would have succeeded, but the DryRun option is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGrant with DryRun=True fails with DryRunOperationException and the exact message and leaves
    ListGrants empty; the same call without DryRun creates a grant that ListGrants shows."""
    kms = ctx.client("kms")
    grantee_principal = f"arn:aws:iam::{ctx.account}:root"

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-grant-dryrun-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-create-grant-dry-run-no-effect"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    before = _list_all_grants(kms, key_id)
    assert before == [], f"expected no pre-existing grants on a fresh key, got {before}"

    code = _err(
        lambda: kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=grantee_principal,
            Operations=["Decrypt"],
            DryRun=True,
        )
    )
    assert code == ("DryRunOperationException", MSG_DRY_RUN), (
        f"expected DryRunOperationException {MSG_DRY_RUN!r}, got {code!r}"
    )

    # effect-absent: no grant was actually persisted by the dry run
    after_dry_run = _list_all_grants(kms, key_id)
    assert after_dry_run == [], f"DryRun=True must not persist a grant, got {after_dry_run}"

    # positive control: the identical call, without DryRun, actually creates a grant
    real = kms.create_grant(
        KeyId=key_id, GranteePrincipal=grantee_principal, Operations=["Decrypt"]
    )
    ctx.on_cleanup(
        lambda gid=real["GrantId"]: kms.revoke_grant(KeyId=key_id, GrantId=gid)
    )
    after_real = _list_all_grants(kms, key_id)
    assert any(g["GrantId"] == real["GrantId"] for g in after_real), (
        f"expected grant {real['GrantId']} to be visible in ListGrants, got {after_real}"
    )


def _list_all_grants(kms, key_id):
    grants = []
    marker = None
    while True:
        kwargs = {"KeyId": key_id}
        if marker:
            kwargs["Marker"] = marker
        resp = kms.list_grants(**kwargs)
        grants.extend(resp.get("Grants", []))
        if not resp.get("Truncated"):
            break
        marker = resp["NextMarker"]
    return grants


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
