"""list-resource-tags-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-resource-tags-empty"
GROUP = 'tags'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceTags returns an empty list for an untagged key, and returns the tag for a
    tagged control key so an always-empty answer cannot pass.
    """
    kms = ctx.client("kms")

    control_key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-suite", "TagValue": "kms-list-resource-tags-empty-control"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=control_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    control_tags = {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=control_key_id)["Tags"]}
    assert control_tags.get("sim2real-suite") == "kms-list-resource-tags-empty-control", (
        f"control key expected tag sim2real-suite=kms-list-resource-tags-empty-control, got {control_tags!r}"
    )

    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    resp = kms.list_resource_tags(KeyId=key_id)
    assert resp["Tags"] == [], f"expected no tags on untagged key, got {resp['Tags']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
