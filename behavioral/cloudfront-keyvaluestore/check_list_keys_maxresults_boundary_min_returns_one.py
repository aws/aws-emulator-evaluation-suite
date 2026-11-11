"""list-keys-maxresults-boundary-min-returns-one."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-keys-maxresults-boundary-min-returns-one"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListKeys with MaxResults at its documented minimum (1) returns exactly one
    item per call and a NextToken whenever more items remain, distinct from the
    default page size (10) and the maximum (50)."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    expected = {f"min-page-{i}" for i in range(3)}
    dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=[{"Key": k, "Value": "v"} for k in expected])

    seen: set[str] = set()
    token = None
    pages = 0
    while True:
        kwargs = {"KvsARN": arn, "MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        page = dp.list_keys(**kwargs)
        pages += 1
        assert len(page["Items"]) == 1, "MaxResults=1 must return exactly one item per page"
        seen.add(page["Items"][0]["Key"])
        token = page.get("NextToken")
        if not token:
            break
        assert pages < 10, "pagination did not terminate"

    assert pages == 3, f"expected exactly 3 pages of 1 item for 3 keys, got {pages}"
    assert seen == expected, f"expected {expected}, saw {seen}"


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
    resp = cf.create_key_value_store(Name=name, Comment="sim2real behavioral check")
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
