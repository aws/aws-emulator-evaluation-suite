"""update-keys-delete-nonexistent-key-is-idempotent-no-op."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-delete-nonexistent-key-is-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateKeys with a Deletes entry naming a key that does not exist is not an error: the whole
    batch, Puts included, applies as if that entry were a no-op."""
    _ensure_awscrt()
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    setup = dp.update_keys(
        KvsARN=arn,
        IfMatch=etag0,
        Puts=[{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}],
    )
    assert setup["ItemCount"] == 2, f"expected 2 items after seeding puts, got {setup['ItemCount']}"
    etag1 = setup["ETag"]

    resp = dp.update_keys(
        KvsARN=arn,
        IfMatch=etag1,
        Puts=[{"Key": "k3", "Value": "v3"}],
        Deletes=[{"Key": "does-not-exist"}],
    )

    # effect present: k3 landed even though the batch also named a nonexistent Delete
    assert resp["ItemCount"] == 3, f"expected 3 items after the batch, got {resp['ItemCount']}"
    got_k3 = dp.get_key(KvsARN=arn, Key="k3")["Value"]
    assert got_k3 == "v3", f"expected k3='v3', got {got_k3!r}"
    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ItemCount"] == 3, f"expected describe to report 3 items, got {described['ItemCount']}"
    assert described["ETag"] == resp["ETag"] != etag1, "the batch must still bump the version"

    # positive control: k1/k2 (never named in any Delete) are untouched
    got_k1 = dp.get_key(KvsARN=arn, Key="k1")["Value"]
    assert got_k1 == "v1", f"expected untouched k1='v1', got {got_k1!r}"
    got_k2 = dp.get_key(KvsARN=arn, Key="k2")["Value"]
    assert got_k2 == "v2", f"expected untouched k2='v2', got {got_k2!r}"


def _ensure_awscrt() -> None:
    """SigV4A signing for this data plane needs awscrt; without it the runner lacks a dependency."""
    from botocore.compat import HAS_CRT

    if not HAS_CRT:
        from fidelity_tests_runner import RequiredToolMissing

        raise RequiredToolMissing(["awscrt"])


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
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
