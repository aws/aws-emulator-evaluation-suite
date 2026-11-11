"""key-value-store-delete-in-use-by-function-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_FUNCTION_CODE = b"""
function handler(event) {
    var request = event.request;
    return request;
}
""".strip()

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_key_value_store_ready(cf, name, *, timeout_s=180, interval_s=3):
    return _poll_until(
        lambda: cf.describe_key_value_store(Name=name),
        lambda r: r["KeyValueStore"]["Status"].upper() == "READY",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"key value store {name} reaching READY",
    )

def _delete_key_value_store_if_present(cf, name):
    try:
        etag = cf.describe_key_value_store(Name=name)["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
            return
        raise
    cf.delete_key_value_store(Name=name, IfMatch=etag)

def _delete_function_if_present(cf, name):
    try:
        etag = cf.describe_function(Name=name)["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchFunctionExists":
            return
        raise
    cf.delete_function(Name=name, IfMatch=etag)

CHECK = "key-value-store-delete-in-use-by-function-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKeyValueStore on a store a CloudFront Function references fails with
    CannotDeleteEntityWhileInUse naming the store and leaves it intact; once the function is deleted the
    same delete succeeds, after which describe and update return EntityNotFound."""
    cf = ctx.client("cloudfront")
    kvs_name = ctx.unique_name("sim2real-behav-kvs-inuse-")
    kvs_resp = cf.create_key_value_store(
        Name=kvs_name,
        Comment="in-use test",
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
    )
    kvs_arn = kvs_resp["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _delete_key_value_store_if_present(cf, kvs_name))
    _wait_key_value_store_ready(cf, kvs_name, timeout_s=180)

    fn_name = ctx.unique_name("sim2real-behav-fn-kvs-")
    cf.create_function(
        Name=fn_name,
        FunctionConfig={
            "Comment": "kvs-inuse test",
            "Runtime": "cloudfront-js-2.0",
            "KeyValueStoreAssociations": {
                "Quantity": 1,
                "Items": [{"KeyValueStoreARN": kvs_arn}],
            },
        },
        FunctionCode=_FUNCTION_CODE,
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
    )
    ctx.on_cleanup(lambda: _delete_function_if_present(cf, fn_name))

    kvs_etag = cf.describe_key_value_store(Name=kvs_name)["ETag"]
    code, message = _error(lambda: cf.delete_key_value_store(Name=kvs_name, IfMatch=kvs_etag))
    assert code == "CannotDeleteEntityWhileInUse", (
        f"expected CannotDeleteEntityWhileInUse while a function references the store, got {code}"
    )
    expected_in_use = f"Cannot delete KeyValueStore {kvs_name} because it is associated with a function"
    assert message == expected_in_use, f"expected {expected_in_use!r}, got {message!r}"

    # Effect absent: the rejected delete left the store untouched.
    still = cf.describe_key_value_store(Name=kvs_name)
    assert still["KeyValueStore"]["Name"] == kvs_name, (
        f"the store must survive the rejected delete, got {still['KeyValueStore']!r}"
    )

    # Restore: remove the only reference, then the SAME delete call succeeds.
    _delete_function_if_present(cf, fn_name)
    fresh_etag = cf.describe_key_value_store(Name=kvs_name)["ETag"]
    cf.delete_key_value_store(Name=kvs_name, IfMatch=fresh_etag)

    gone_code, gone_message = _error(lambda: cf.describe_key_value_store(Name=kvs_name))
    assert gone_code == "EntityNotFound", (
        f"expected EntityNotFound once the store is actually deleted, got {gone_code}"
    )
    assert gone_message == "The specified KeyValueStore does not exist.", (
        f"expected AWS's exact not-found message for the deleted store, got {gone_message!r}"
    )

    # A mutation on the dead id fails the same specific way, not with some other error.
    update_code, update_message = _error(
        lambda: cf.update_key_value_store(Name=kvs_name, IfMatch=fresh_etag, Comment="post-delete")
    )
    assert update_code == "EntityNotFound", (
        f"expected EntityNotFound updating a deleted store, got {update_code}"
    )
    assert update_message == "The specified KeyValueStore does not exist.", (
        f"expected AWS's exact not-found message updating the deleted store, got {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
