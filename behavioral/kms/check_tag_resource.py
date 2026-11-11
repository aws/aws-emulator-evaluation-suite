"""tag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource"
GROUP = 'tags'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags; ListResourceTags returns them."""
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    tags = [
        {"TagKey": "sim2real-env", "TagValue": "behavioral"},
        {"TagKey": "sim2real-suite", "TagValue": "kms"},
    ]
    kms.tag_resource(KeyId=key_id, Tags=tags)

    resp = kms.list_resource_tags(KeyId=key_id)
    tag_map = {t["TagKey"]: t["TagValue"] for t in resp["Tags"]}
    assert tag_map.get("sim2real-env") == "behavioral", (
        f"expected sim2real-env=behavioral, got {tag_map.get('sim2real-env')!r} in {tag_map!r}"
    )
    assert tag_map.get("sim2real-suite") == "kms", (
        f"expected sim2real-suite=kms, got {tag_map.get('sim2real-suite')!r} in {tag_map!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
