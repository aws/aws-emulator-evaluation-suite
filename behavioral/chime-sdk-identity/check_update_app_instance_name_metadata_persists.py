"""update-app-instance-name-metadata-persists."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "update-app-instance-name-metadata-persists"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAppInstance persists the new Name/Metadata and advances LastUpdatedTimestamp."""
    # chime-sdk-identity's control plane is only reachable in us-east-1 on real AWS; the
    # emulator shares one endpoint regardless of region, so only the real-AWS client is pinned.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"), Metadata="original", ClientRequestToken=uuid.uuid4().hex
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=arn))

    before = client.describe_app_instance(AppInstanceArn=arn)["AppInstance"]
    # A never-updated AppInstance carries no LastUpdatedTimestamp at all (confirmed on real
    # AWS: a fresh DescribeAppInstance returns only AppInstanceArn/Name/CreatedTimestamp/
    # Metadata) -- so the "before" watermark is CreatedTimestamp until the first update.
    before_watermark = before.get("LastUpdatedTimestamp", before["CreatedTimestamp"])
    new_name = ctx.unique_name("sim2real-chime-ai-updated-")

    # LastUpdatedTimestamp has millisecond resolution, so a single update issued in the same
    # millisecond as the create could tie. Re-issue the (idempotent, same-target) update inside
    # a bounded poll until the server-observed timestamp actually advances, rather than paying a
    # fixed sleep on every run.
    def _attempt():
        client.update_app_instance(AppInstanceArn=arn, Name=new_name, Metadata="updated-metadata")
        return client.describe_app_instance(AppInstanceArn=arn)["AppInstance"]

    after = _poll_until(
        _attempt,
        lambda desc: desc.get("LastUpdatedTimestamp") is not None
        and desc["LastUpdatedTimestamp"] > before_watermark,
        timeout_s=15.0,
        interval_s=0.5,
    )
    assert after["Name"] == new_name, f"expected Name={new_name!r}, got {after['Name']!r}"
    assert after["Metadata"] == "updated-metadata", (
        f"expected Metadata='updated-metadata', got {after['Metadata']!r}"
    )
    assert after["LastUpdatedTimestamp"] > before_watermark, (
        f"expected LastUpdatedTimestamp to advance past {before_watermark!r}, "
        f"got {after.get('LastUpdatedTimestamp')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 15.0, interval_s: float = 0.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
