"""cf-keyvaluestore-put-key-visible-to-function-at-edge."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cf-keyvaluestore-put-key-visible-to-function-at-edge"
GROUP = 'functions'
SERVICES = ['cloudfront']

# cloudfront-js-2.0 is the only runtime with the `kvs` module. `cf.kvs()` resolves the function's
# single KeyValueStoreAssociation, so the ARN is never named in the code — the association is what
# is under test.
_FUNCTION_CODE_TEMPLATE = """
import cf from 'cloudfront';
const store = cf.kvs();
async function handler(event) {
    const value = await store.get('%s');
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {},
        body: value
    };
}
"""

_EVENT = json.dumps({
    "version": "1.0",
    "context": {"eventType": "viewer-request"},
    "viewer": {"ip": "203.0.113.9"},
    "request": {"method": "GET", "uri": "/", "querystring": {}, "headers": {}, "cookies": {}},
}).encode()


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _force_delete_function(cf, name: str) -> None:
    """ETag-guarded DeleteFunction."""
    cf.delete_function(Name=name, IfMatch=cf.describe_function(Name=name)["ETag"])


def _force_delete_kvs(cf, kvs_client, name: str, arn: str, key: str) -> None:
    """Empty the store on its data plane, then ETag-guarded DeleteKeyValueStore.

    Both ETags are re-read here because every write rotates them."""
    try:
        kvs_client.delete_key(
            KvsARN=arn, Key=key,
            IfMatch=kvs_client.describe_key_value_store(KvsARN=arn)["ETag"],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "ResourceNotFoundException"):
            raise
    cf.delete_key_value_store(Name=name, IfMatch=cf.describe_key_value_store(Name=name)["ETag"])


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A key written on the cloudfront-keyvaluestore data plane is read back by the function's
    JavaScript, run at the DEVELOPMENT stage via TestFunction (no distribution deployed).
    """
    cf = ctx.client("cloudfront")
    kvs_name = ctx.unique_name("sim2real-behav-kvs-")

    created = cf.create_key_value_store(
        Name=kvs_name, Comment="sim2real kvs at edge",
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    kvs_arn = created["KeyValueStore"]["ARN"]
    key = "sim2real-edge-key"
    # Registered before the READY poll: a store that never becomes READY still exists and still
    # has to be deleted.
    ctx.on_cleanup(lambda: _force_delete_kvs(cf, ctx.client("cloudfront-keyvaluestore"),
                                             kvs_name, kvs_arn, key))

    status = _poll_until(
        lambda: cf.describe_key_value_store(Name=kvs_name)["KeyValueStore"]["Status"],
        lambda s: s == "READY",
        timeout_s=300, interval_s=5,
        description=f"key-value store {kvs_name} to reach READY",
    )
    assert status == "READY", f"store status is {status!r}, not READY"

    kvs = ctx.client("cloudfront-keyvaluestore")

    # The data plane's ETag is its own optimistic-concurrency token, distinct from the control
    # plane's, and PutKey requires the current one.
    before = kvs.describe_key_value_store(KvsARN=kvs_arn)
    assert before["ItemCount"] == 0, f"a fresh store reports {before['ItemCount']!r} items"

    value = "edge-visible-value-42"
    put = kvs.put_key(KvsARN=kvs_arn, Key=key, Value=value, IfMatch=before["ETag"])
    assert put["ItemCount"] == 1, f"ItemCount after one PutKey is {put['ItemCount']!r}"

    got = kvs.get_key(KvsARN=kvs_arn, Key=key)
    assert got["Value"] == value, f"GetKey returned {got['Value']!r}, wrote {value!r}"

    fn_name = ctx.unique_name("sim2real-behav-fn-kvs-")
    fn = cf.create_function(
        Name=fn_name,
        FunctionConfig={
            "Comment": "sim2real kvs read at edge",
            "Runtime": "cloudfront-js-2.0",
            "KeyValueStoreAssociations": {"Quantity": 1, "Items": [{"KeyValueStoreARN": kvs_arn}]},
        },
        FunctionCode=(_FUNCTION_CODE_TEMPLATE % key).encode(),
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    ctx.on_cleanup(lambda: _force_delete_function(cf, fn_name))

    # A PutKey reaches the function runtime asynchronously: TestFunction can still fail with
    # "KeyNotFound" after GetKey already sees the key, so poll the function's own output.
    def _serve() -> dict:
        r = cf.test_function(Name=fn_name, IfMatch=fn["ETag"], EventObject=_EVENT)["TestResult"]
        body = None
        if not r.get("FunctionErrorMessage"):
            body = json.loads(r["FunctionOutput"])["response"]["body"]
        return {"error": r.get("FunctionErrorMessage"), "body": body,
                "compute": r.get("ComputeUtilization")}

    served = _poll_until(
        _serve,
        lambda r: not r["error"],
        timeout_s=240, interval_s=10,
        description="the edge function to resolve the key it was given (KVS -> runtime propagation)",
    )

    assert not served["error"], (
        f"the edge function errored reading the key-value store: {served['error']!r}"
    )
    body = served["body"]
    # A CloudFront Functions response body is returned as {"encoding": ..., "data": ...} when the
    # runtime normalises it, and as a bare string otherwise; take the payload structurally rather
    # than assuming either form.
    payload = body["data"] if isinstance(body, dict) else body
    assert payload == value, (
        f"the edge function read the wrong value from the key-value store: response body was "
        f"{body!r}, the store holds {value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
