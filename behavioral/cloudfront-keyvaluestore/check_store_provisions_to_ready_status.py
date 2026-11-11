"""store-provisions-to-ready-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "store-provisions-to-ready-status"
GROUP = "lifecycle"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A freshly-created key value store transitions Provisioning -> Ready, and the
    data-plane view of a Ready, empty store reports zero items/bytes."""
    cf = ctx.client("cloudfront")
    dp = ctx.client("cloudfront-keyvaluestore")
    name = ctx.unique_name("sim2real-kvs-")

    resp = cf.create_key_value_store(Name=name, Comment="sim2real behavioral lifecycle check")
    arn = resp["KeyValueStore"]["ARN"]
    initial_status = resp["KeyValueStore"]["Status"].upper()

    def _cleanup() -> None:
        d = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=d["ETag"])

    ctx.on_cleanup(_cleanup)

    # Real AWS documents the lifecycle as Provisioning -> Ready (or Import failed).
    # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/kvs-with-functions-create.html
    assert initial_status in ("PROVISIONING", "READY"), f"unexpected initial status {initial_status}"

    deadline = time.monotonic() + 180.0
    status = initial_status
    while status != "READY" and time.monotonic() < deadline:
        time.sleep(3.0)
        d = cf.describe_key_value_store(Name=name)
        status = d["KeyValueStore"]["Status"].upper()
        assert "FAIL" not in status, f"store entered a failure status: {status}"

    assert status == "READY", f"store never reached READY within timeout, last status={status}"

    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ItemCount"] == 0, f"expected ItemCount 0 for a fresh empty store, got {described['ItemCount']!r}"
    assert described["TotalSizeInBytes"] == 0, (
        f"expected TotalSizeInBytes 0 for a fresh empty store, got {described['TotalSizeInBytes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
