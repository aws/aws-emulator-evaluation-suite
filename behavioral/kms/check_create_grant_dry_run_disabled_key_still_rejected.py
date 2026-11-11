"""create-grant-dry-run-disabled-key-still-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-grant-dry-run-disabled-key-still-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]
MSG_DRY_RUN = "The request would have succeeded, but the DryRun option is set."
MSG_DISABLED = "{key_arn} is disabled."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGrant with DryRun=true on a disabled key fails DisabledException and creates no grant,
    while on an enabled key (and after EnableKey) it fails DryRunOperationException: DryRun does
    not bypass the key-state check."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    grantee = f"arn:aws:iam::{account}:root"

    # Positive control: on an enabled key the request would succeed, so DryRun raises.
    enabled_key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grant-dryrun-enabled-")
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=enabled_key_id, PendingWindowInDays=7))

    code_enabled = _err(
        lambda: kms.create_grant(
            KeyId=enabled_key_id,
            GranteePrincipal=grantee,
            Operations=["Encrypt"],
            DryRun=True,
        )
    )
    assert code_enabled == ("DryRunOperationException", MSG_DRY_RUN), code_enabled

    disabled_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grant-dryrun-disabled-")
    )["KeyMetadata"]
    disabled_key_id, disabled_key_arn = disabled_meta["KeyId"], disabled_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=disabled_key_id, PendingWindowInDays=7))
    kms.disable_key(KeyId=disabled_key_id)

    described = kms.describe_key(KeyId=disabled_key_id)["KeyMetadata"]
    assert described["KeyState"] == "Disabled", described["KeyState"]

    code_disabled = _err(
        lambda: kms.create_grant(
            KeyId=disabled_key_id,
            GranteePrincipal=grantee,
            Operations=["Encrypt"],
            DryRun=True,
        )
    )
    expected_disabled = ("DisabledException", MSG_DISABLED.format(key_arn=disabled_key_arn))
    assert code_disabled == expected_disabled, code_disabled

    grants = kms.list_grants(KeyId=disabled_key_id)["Grants"]
    assert grants == [], grants

    # Restore: re-enabling shows the DisabledException was about the key state.
    kms.enable_key(KeyId=disabled_key_id)
    restored = kms.describe_key(KeyId=disabled_key_id)["KeyMetadata"]
    assert restored["KeyState"] == "Enabled", restored["KeyState"]

    code_restored = _err(
        lambda: kms.create_grant(
            KeyId=disabled_key_id,
            GranteePrincipal=grantee,
            Operations=["Encrypt"],
            DryRun=True,
        )
    )
    assert code_restored == ("DryRunOperationException", MSG_DRY_RUN), code_restored


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
