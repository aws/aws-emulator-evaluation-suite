"""list-keys-default-max-results-is-ten."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-keys-default-max-results-is-ten"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListKeys without an explicit MaxResults defaults to a page size of 10 and
    returns a NextToken when more items remain."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    keys = [f"default-page-{i}" for i in range(15)]
    puts = [{"Key": k, "Value": "v"} for k in keys]
    resp = dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=puts)
    assert resp["ItemCount"] == 15, f"expected ItemCount 15 after 15 puts, got {resp['ItemCount']}"

    first_page = dp.list_keys(KvsARN=arn)
    assert len(first_page["Items"]) == 10, "default MaxResults must be 10"
    next_token = first_page.get("NextToken")
    assert next_token, "a NextToken must be returned when more items remain"

    second_page = dp.list_keys(KvsARN=arn, NextToken=next_token)
    assert len(second_page["Items"]) == 5, f"expected 5 remaining items, got {len(second_page['Items'])}"
    assert not second_page.get("NextToken"), (
        f"expected no NextToken on the final page, got {second_page.get('NextToken')!r}"
    )

    all_seen = {i["Key"] for i in first_page["Items"]} | {i["Key"] for i in second_page["Items"]}
    assert all_seen == set(keys), f"expected all 15 keys across both pages, got {sorted(all_seen)}"


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
