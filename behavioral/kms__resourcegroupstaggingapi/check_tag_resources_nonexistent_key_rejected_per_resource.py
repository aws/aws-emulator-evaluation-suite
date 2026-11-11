"""tag-resources-nonexistent-key-rejected-per-resource."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-key-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["kms", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResources over one live KMS key and one well-formed absent key succeeds, tags the live
    key, and lists only the absent one in FailedResourcesMap with KMS's NotFoundException/400.
    """
    kms = ctx.client("kms")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
                            Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["KeyId"]
    live_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    ghost_arn = f"arn:aws:kms:{ctx.region}:{account}:key/{uuid.uuid4()}"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent key "
        f"{ghost_arn!r} -- the live key {live_arn!r} must not fail and the absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "NotFoundException", (
        f"the per-resource ErrorCode for an absent key was {detail['ErrorCode']!r}, expected "
        f"KMS's own NotFoundException"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected = f"Key '{ghost_arn}' does not exist"
    assert detail["ErrorMessage"] == expected, (
        f"the per-resource ErrorMessage for an absent key was {detail['ErrorMessage']!r}, "
        f"expected {expected!r}"
    )

    def _native_tags():
        return {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=key_id)["Tags"]}

    native_view = _poll_until(_native_tags, lambda m: m.get(key) == "partial", timeout_s=180.0)
    assert native_view.get(key) == "partial", (
        f"the live key {live_arn!r} never received {key}=partial (saw {native_view!r}) -- a "
        f"partial failure must still apply the tags that succeeded"
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
