"""key-tags-visible-through-get-resources-both-directions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "key-tags-visible-through-get-resources-both-directions"
GROUP = "tagging-discovery"
SERVICES = ["kms", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag written by KMS TagResource is found by tagging-API GetResources, and a tag written by
    tagging-API TagResources is read back by KMS ListResourceTags on the same key."""
    kms = ctx.client("kms")
    rgt = ctx.client("resourcegroupstaggingapi")

    native_key = ctx.unique_name("sim2real-behav-nk-")
    native_value = ctx.unique_name("sim2real-behav-nv-")
    rgt_key = ctx.unique_name("sim2real-behav-rk-")
    rgt_value = ctx.unique_name("sim2real-behav-rv-")

    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    # KMS requires a pending window of at least 7 days before a key is destroyed.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Direction 1: native write, cross-service read (the tagging index is eventually consistent).
    kms.tag_resource(KeyId=key_id, Tags=[{"TagKey": native_key, "TagValue": native_value}])
    found = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": native_key, "Values": [native_value]}]
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(found) == 1, f"GetResources matched {len(found)} resources, expected exactly 1: {found!r}"
    assert found[0]["ResourceARN"] == key_arn, (
        f"discovered ARN {found[0]['ResourceARN']!r} does not equal the key's own ARN {key_arn!r}"
    )

    # Direction 2: cross-service write (TagResources), native read (KMS ListResourceTags).
    tagged = rgt.tag_resources(ResourceARNList=[key_arn], Tags={rgt_key: rgt_value})
    assert tagged["FailedResourcesMap"] == {}, (
        f"TagResources on a live key reported per-resource failures: {tagged['FailedResourcesMap']!r}"
    )

    def _native_tags():
        return {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=key_id)["Tags"]}

    native_view = _poll_until(
        _native_tags, lambda m: m.get(rgt_key) == rgt_value, timeout_s=180.0,
    )
    assert native_view.get(rgt_key) == rgt_value, (
        f"KMS's own ListResourceTags reports {native_view!r}, missing {rgt_key}={rgt_value!r} "
        f"after a tagging-api TagResources write"
    )
    # The native key written via KMS's own TagResource must still be present too.
    assert native_view.get(native_key) == native_value, (
        f"KMS's own ListResourceTags lost the natively-written tag {native_key}={native_value!r}: "
        f"{native_view!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
