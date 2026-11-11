"""list-keys-pagination-covers-all-items."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-keys-pagination-covers-all-items"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating ListKeys with a small MaxResults page size, following NextToken,
    yields every key exactly once with no duplicates or omissions."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    expected_keys = {f"page-key-{i}" for i in range(12)}
    puts = [{"Key": k, "Value": f"value-for-{k}"} for k in expected_keys]
    update_resp = dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=puts)
    assert update_resp["ItemCount"] == 12, (
        f"expected ItemCount 12 after seeding 12 keys, got {update_resp['ItemCount']!r}"
    )

    seen_keys: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"KvsARN": arn, "MaxResults": 5}
        if next_token:
            kwargs["NextToken"] = next_token
        page = dp.list_keys(**kwargs)
        pages += 1
        items = page.get("Items", [])
        assert len(items) <= 5, f"page {pages} returned {len(items)} items, exceeding MaxResults=5"
        seen_keys.extend(item["Key"] for item in items)
        next_token = page.get("NextToken")
        if not next_token:
            break
        assert pages < 20, "pagination did not terminate within a sane number of pages"

    assert pages >= 3, f"expected at least 3 pages of 5 for 12 items, got {pages} pages"
    assert set(seen_keys) == expected_keys, (
        f"missing={expected_keys - set(seen_keys)!r} extra={set(seen_keys) - expected_keys!r}"
    )
    assert len(seen_keys) == len(expected_keys), (
        f"pagination must not repeat items: saw {len(seen_keys)} items across {pages} pages, "
        f"expected exactly {len(expected_keys)}"
    )


def _wait_for_store_ready(ctx, name, timeout_s=180.0, interval_s=3.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        d = cf.describe_key_value_store(Name=name)
        status = d["KeyValueStore"]["Status"].upper()
        if status == "READY":
            return
        assert "FAIL" not in status, f"store entered a failure status: {status}"
        time.sleep(interval_s)
    raise AssertionError(f"store never reached READY within timeout, last status={status}")


def _create_ready_store(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")
    resp = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        d = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=d["ETag"])

    ctx.on_cleanup(_cleanup)
    _wait_for_store_ready(ctx, name)
    return {"name": name, "arn": arn}


def _dp_etag(dp, arn):
    return dp.describe_key_value_store(KvsARN=arn)["ETag"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
