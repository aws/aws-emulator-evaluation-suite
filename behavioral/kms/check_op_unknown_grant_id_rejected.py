"""op-unknown-grant-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-unknown-grant-id-rejected"
GROUP = 'grants'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unknown GrantId is refused: RevokeGrant with NotFoundException, RetireGrant (ARN KeyId)
    with AccessDeniedException; each negative follows a positive control on a real grant.
    """
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    meta = kms.create_key(
        Description=ctx.unique_name("kms-op-grantid-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    bogus = "0" * 64

    # Positive control: a real grant with the same KeyId form is revocable, so the call is not
    # rejecting everything.
    real_1 = kms.create_grant(KeyId=key_id, GranteePrincipal=root_arn, Operations=["Encrypt"])["GrantId"]
    kms.revoke_grant(KeyId=key_id, GrantId=real_1)
    live_1 = [g["GrantId"] for g in kms.list_grants(KeyId=key_id)["Grants"]]
    assert real_1 not in live_1, f"positive control: RevokeGrant on a real id must remove it; still in {live_1!r}"

    code, message = _error(lambda: kms.revoke_grant(KeyId=key_id, GrantId=bogus))
    assert code == "NotFoundException", f"RevokeGrant unknown id -> got {code}"
    assert message == f"Grant ID {bogus} not found", message

    # Positive control: RetireGrant with an ARN KeyId on a real grant actually retires it.
    real_2 = kms.create_grant(
        KeyId=key_arn, GranteePrincipal=root_arn, RetiringPrincipal=root_arn, Operations=["Decrypt"]
    )["GrantId"]
    kms.retire_grant(KeyId=key_arn, GrantId=real_2)
    live_2 = [g["GrantId"] for g in kms.list_grants(KeyId=key_id)["Grants"]]
    assert real_2 not in live_2, f"positive control: RetireGrant(ARN KeyId) on a real id must remove it; still in {live_2!r}"

    code2, message2 = _error(lambda: kms.retire_grant(KeyId=key_arn, GrantId=bogus))
    assert code2 == "AccessDeniedException", f"RetireGrant unknown id (ARN) -> got {code2}"
    assert message2 == (
        f"User: {caller['Arn']} is not authorized to perform: kms:RetireGrant on this resource "
        "because the resource does not exist in this Region, no resource-based policies allow "
        "access, or a resource-based policy explicitly denies access"
    ), message2

    # RetireGrant requires an ARN KeyId: a bare key id is rejected as an invalid ARN for any
    # GrantId, so this KeyId-shape rule is asserted with a real grant, not the bogus id.
    real_3 = kms.create_grant(
        KeyId=key_id, GranteePrincipal=root_arn, RetiringPrincipal=root_arn, Operations=["Decrypt"]
    )["GrantId"]
    ctx.on_cleanup(lambda _k=key_arn, _g=real_3: kms.revoke_grant(KeyId=_k, GrantId=_g))
    code3, message3 = _error(lambda: kms.retire_grant(KeyId=key_id, GrantId=real_3))
    assert code3 == "NotFoundException", (
        f"RetireGrant with non-ARN KeyId, even on a REAL grant, -> got {code3}"
    )
    assert message3 == f"Invalid arn {key_id}", message3


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
