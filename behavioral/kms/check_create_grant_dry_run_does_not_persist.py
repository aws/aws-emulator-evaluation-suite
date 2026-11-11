"""create-grant-dry-run-does-not-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-grant-dry-run-does-not-persist"
GROUP = "overly-permissive"
SERVICES = ["kms"]
MSG_DRY_RUN = "The request would have succeeded, but the DryRun option is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGrant with DryRun=true raises DryRunOperationException and persists no grant, while
    the identical call without DryRun creates a grant that ListGrants returns."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grant-dryrun-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-grant-dryrun-does-not-persist"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    account = sts.get_caller_identity()["Account"]
    grantee = f"arn:aws:iam::{account}:root"

    code = _err(
        lambda: kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=grantee,
            Operations=["Encrypt", "Decrypt"],
            DryRun=True,
        )
    )
    assert code == ("DryRunOperationException", MSG_DRY_RUN), (
        f"expected DryRunOperationException {MSG_DRY_RUN!r}, got {code!r}"
    )

    grants_after_dry_run = kms.list_grants(KeyId=key_id)["Grants"]
    assert grants_after_dry_run == [], f"expected no grants, got {grants_after_dry_run}"

    # Positive control: the SAME call without DryRun really creates a grant.
    created = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee,
        Operations=["Encrypt", "Decrypt"],
    )
    grant_id = created["GrantId"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    grants_after_real_call = kms.list_grants(KeyId=key_id)["Grants"]
    assert any(g["GrantId"] == grant_id for g in grants_after_real_call), (
        f"expected grant {grant_id} to be listed, got {grants_after_real_call}"
    )


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
