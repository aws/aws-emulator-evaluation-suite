"""update-key-description."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-key-description"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateKeyDescription replaces the description and is immediately visible via DescribeKey."""
    kms = ctx.client("kms")
    original = ctx.unique_name("kms-desc-orig-")
    key_id = kms.create_key(
        Description=original,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Description"]
    assert described == original, f"expected initial description {original!r}, got {described!r}"

    updated = ctx.unique_name("kms-desc-new-")
    kms.update_key_description(KeyId=key_id, Description=updated)
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Description"]
    assert described == updated, f"expected updated description {updated!r}, got {described!r}"

    # description may be cleared to the empty string
    kms.update_key_description(KeyId=key_id, Description="")
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Description"]
    assert described == "", f"expected description cleared to '', got {described!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
