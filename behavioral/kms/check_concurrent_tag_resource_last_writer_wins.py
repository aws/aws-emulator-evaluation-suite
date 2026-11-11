"""concurrent-tag-resource-last-writer-wins."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent TagResource calls on the same tag key settle on one stable, consistent value."""
    kms = ctx.client("kms")
    key_id = _create_symmetric_key(ctx)
    tag_key = "sim2real-environment"
    candidate_values = ["blue-candidate", "green-candidate"]

    barrier = threading.Barrier(len(candidate_values))

    def set_tag(value: str) -> None:
        barrier.wait(timeout=10)
        kms.tag_resource(KeyId=key_id, Tags=[{"TagKey": tag_key, "TagValue": value}])

    with ThreadPoolExecutor(max_workers=len(candidate_values)) as pool:
        futures = [pool.submit(set_tag, value) for value in candidate_values]
        for future in futures:
            future.result(timeout=30)

    final_value = _current_tag_value(kms, key_id, tag_key)
    assert final_value in candidate_values, (
        f"final tag value {final_value!r} is not one of the racing writers' values {candidate_values}"
    )

    # re-read repeatedly: the resolved value must be stable, not flapping or corrupted into
    # a merged/duplicated state
    for _ in range(5):
        time.sleep(1)
        reread = _current_tag_value(kms, key_id, tag_key)
        assert reread == final_value, (
            f"tag value drifted from {final_value!r} to {reread!r} on re-read; "
            "the resolved value must be stable, not flapping or corrupted"
        )


def _current_tag_value(kms, key_id: str, tag_key: str) -> str:
    tags_ = kms.list_resource_tags(KeyId=key_id)["Tags"]
    matching = [t["TagValue"] for t in tags_ if t["TagKey"] == tag_key]
    assert len(matching) == 1, f"expected exactly one value for tag {tag_key!r}, got {matching}"
    return matching[0]


def _create_symmetric_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-kms-key-"),
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
