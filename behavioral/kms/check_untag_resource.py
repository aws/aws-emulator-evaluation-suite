"""untag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource"
GROUP = 'tags'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes specific tags."""
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    tags = [
        {"TagKey": "sim2real-keep", "TagValue": "yes"},
        {"TagKey": "sim2real-remove", "TagValue": "yes"},
    ]
    kms.tag_resource(KeyId=key_id, Tags=tags)
    kms.untag_resource(KeyId=key_id, TagKeys=["sim2real-remove"])

    resp = kms.list_resource_tags(KeyId=key_id)
    tag_map = {t["TagKey"]: t["TagValue"] for t in resp["Tags"]}
    assert "sim2real-keep" in tag_map, f"expected sim2real-keep to survive UntagResource, tags now {tag_map}"
    assert "sim2real-remove" not in tag_map, f"expected sim2real-remove to be gone after UntagResource, tags now {tag_map}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
