"""create-grant-on-disabled-key-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "create-grant-on-disabled-key-fails"
GROUP = 'grants'
SERVICES = ['kms']
MSG_DISABLED = "{key_arn} is disabled."


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGrant on a disabled KMS key must fail with DisabledException; the same call succeeds
    once the key is re-enabled."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    key_meta = kms.create_key(
        Description=ctx.unique_name("kms-grantdisabled-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-grantdisabled"}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    account = sts.get_caller_identity()["Account"]
    grantee = f"arn:aws:iam::{account}:root"

    # --- Positive control, key enabled: the account and grantee ARN are otherwise fine.
    control_grant_id = kms.create_grant(
        KeyId=key_id, GranteePrincipal=grantee, Operations=["Encrypt"]
    )["GrantId"]
    control_grants = kms.list_grants(KeyId=key_id)["Grants"]
    assert any(g["GrantId"] == control_grant_id for g in control_grants), (
        f"expected grant {control_grant_id} to be listed while the key is enabled, "
        f"got {control_grants}"
    )
    kms.revoke_grant(KeyId=key_id, GrantId=control_grant_id)

    # --- Break exactly one thing.
    kms.disable_key(KeyId=key_id)

    got = _err(
        lambda: kms.create_grant(
            KeyId=key_id, GranteePrincipal=grantee, Operations=["Encrypt"]
        )
    )
    expected = ("DisabledException", MSG_DISABLED.format(key_arn=key_arn))
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # --- Effect absent, via an independent read.
    grants_while_disabled = kms.list_grants(KeyId=key_id)["Grants"]
    assert not any(g["GranteePrincipal"] == grantee for g in grants_while_disabled), (
        f"the rejected CreateGrant must not have created a grant, got {grants_while_disabled}"
    )

    # --- Restore, then the identical call now succeeds.
    kms.enable_key(KeyId=key_id)
    restored_grant_id = kms.create_grant(
        KeyId=key_id, GranteePrincipal=grantee, Operations=["Encrypt"]
    )["GrantId"]
    ctx.on_cleanup(lambda _g=restored_grant_id: kms.revoke_grant(KeyId=key_id, GrantId=_g))
    grants_after_restore = kms.list_grants(KeyId=key_id)["Grants"]
    assert any(g["GrantId"] == restored_grant_id for g in grants_after_restore), (
        f"expected grant {restored_grant_id} to be listed after re-enabling the key, "
        f"got {grants_after_restore}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
