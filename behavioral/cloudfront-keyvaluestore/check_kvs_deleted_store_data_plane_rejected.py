"""kvs-deleted-store-data-plane-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kvs-deleted-store-data-plane-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


class _UnexpectedSuccess(AssertionError):
    """The call the check expected to be REJECTED succeeded."""


def _error_code(fn):
    """The (code, HTTP status, message) fn() raised; success raises _UnexpectedSuccess."""
    try:
        fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message"),
        )
    raise _UnexpectedSuccess("the call succeeded but real AWS rejects it")


def _create_kvs(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-kvs-")
    created = cf.create_key_value_store(Name=name, Comment="sim2real-behav")
    ctx.on_cleanup(lambda: _delete_kvs_if_present(ctx, name))
    arn = created["KeyValueStore"]["ARN"]
    _poll_until(
        lambda: cf.describe_key_value_store(Name=name)["KeyValueStore"]["Status"],
        lambda s: s == "READY",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"KeyValueStore {name} READY",
    )
    return {"arn": arn, "name": name, "id": created["KeyValueStore"]["Id"]}


def _delete_kvs_if_present(ctx, name):
    """Delete the store unless it is already gone (EntityNotFound); other errors propagate."""
    cf = ctx.client("cloudfront")
    try:
        etag = cf.describe_key_value_store(Name=name)["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
            return
        raise
    cf.delete_key_value_store(Name=name, IfMatch=etag)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a KeyValueStore is deleted, Describe on its ARN returns ConflictException (409) while
    key operations return ResourceNotFoundException (404), as does Describe on a never-existed ARN.
    """
    doomed = _create_kvs(ctx)
    # The sibling store is the positive control and keeps the data plane addressable: the
    # <account>.cloudfront-kvs.global.api.aws host does not resolve for an account with no store.
    survivor = _create_kvs(ctx)
    kvs = ctx.client("cloudfront-keyvaluestore")
    cf = ctx.client("cloudfront")
    # The store ARN is global (no region) and ends in the store Id, not its name.
    expected_arn = f"arn:aws:cloudfront::{ctx.account}:key-value-store/{doomed['id']}"
    assert doomed["arn"] == expected_arn, f"expected store ARN {expected_arn!r}, got {doomed['arn']!r}"

    # The doomed store serves the data plane before the delete.
    seeded = kvs.put_key(
        KvsARN=doomed["arn"], Key="doomed-key", Value="present",
        IfMatch=kvs.describe_key_value_store(KvsARN=doomed["arn"])["ETag"],
    )
    assert seeded["ItemCount"] == 1, (
        f"the doomed store did not accept a key before deletion: ItemCount "
        f"{seeded['ItemCount']!r}"
    )
    settled = seeded["ETag"]
    got_value = kvs.get_key(KvsARN=doomed["arn"], Key="doomed-key")["Value"]
    assert got_value == "present", f"GetKey on the doomed store returned {got_value!r}, expected 'present'"
    doomed_keys = [i["Key"] for i in kvs.list_keys(KvsARN=doomed["arn"], MaxResults=50)["Items"]]
    assert doomed_keys == ["doomed-key"], f"ListKeys on the doomed store returned {doomed_keys!r}, expected ['doomed-key']"

    # Delete the store resource on the control plane.
    cf.delete_key_value_store(
        Name=doomed["name"], IfMatch=cf.describe_key_value_store(Name=doomed["name"])["ETag"]
    )

    gone = doomed["arn"]

    def _describe_outcome():
        """(code, status) of the failure, or 'STILL-SERVING' while the delete may be in flight.

        Polled because the delete is a control-plane write that the first read could race.
        """
        try:
            kvs.describe_key_value_store(KvsARN=gone)
        except ClientError as exc:
            return (
                exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            )
        return "STILL-SERVING"

    describe_outcome = _poll_until(
        _describe_outcome,
        lambda code: code != "STILL-SERVING",
        timeout_s=60.0,
        interval_s=3.0,
        description="DescribeKeyValueStore on the deleted store failing",
    )
    describe_code, describe_status = describe_outcome
    assert describe_status == 409, f"DescribeKeyValueStore on the deleted store: expected HTTP 409, got {describe_status!r}"
    assert describe_code == "ConflictException", (
        f"DescribeKeyValueStore on the DELETED store returned {describe_code!r}; real AWS "
        f"returns 'ConflictException' (HTTP 409) — the tombstone, distinct from the "
        f"ResourceNotFoundException a never-existed ARN gets"
    )

    # The control plane reads EntityNotFound 404 by name.
    cp_code, cp_status, cp_message = _error_code(lambda: cf.describe_key_value_store(Name=doomed["name"]))
    assert (cp_code, cp_status) == ("EntityNotFound", 404), (
        f"cloudfront DescribeKeyValueStore on the deleted store returned {cp_code!r}/{cp_status!r}, "
        f"expected EntityNotFound/404"
    )
    expected_message = "The specified KeyValueStore does not exist."
    assert cp_message == expected_message, f"expected the message {expected_message!r}, got {cp_message!r}"
    listed, marker = [], None
    while True:
        page = cf.list_key_value_stores(**({"Marker": marker} if marker else {}))["KeyValueStoreList"]
        listed += [i.get("Name") for i in page.get("Items", []) or []]
        marker = page.get("NextMarker")
        if not marker:
            break
    assert doomed["name"] not in listed, f"deleted store {doomed['name']!r} is still listed by ListKeyValueStores"

    others = {
        "GetKey": lambda: kvs.get_key(KvsARN=gone, Key="doomed-key"),
        "ListKeys": lambda: kvs.list_keys(KvsARN=gone, MaxResults=50),
        "PutKey": lambda: kvs.put_key(
            KvsARN=gone, Key="after-delete", Value="v", IfMatch=settled
        ),
        "DeleteKey": lambda: kvs.delete_key(KvsARN=gone, Key="doomed-key", IfMatch=settled),
        "UpdateKeys": lambda: kvs.update_keys(
            KvsARN=gone, IfMatch=settled, Puts=[{"Key": "after-delete", "Value": "v"}]
        ),
    }
    observed = {op: _error_code(call) for op, call in others.items()}
    assert set(observed.values()) == {("ResourceNotFoundException", 404, "No such Key-Value-Store exists")}, (
        f"the deleted store's key operations returned {observed!r}; real AWS returns "
        f"ResourceNotFoundException (HTTP 404, 'No such Key-Value-Store exists') for every one of the five"
    )

    # the same code answers for an ARN that never named a store, which is why Describe's
    # ConflictException above is the only signal separating the two states
    never = f"{gone.rsplit('/', 1)[0]}/00000000-0000-0000-0000-000000000000"
    never_code, never_status, never_message = _error_code(lambda: kvs.describe_key_value_store(KvsARN=never))
    assert never_status == 404, f"DescribeKeyValueStore on a never-existed ARN: expected HTTP 404, got {never_status!r}"
    assert never_code == "ResourceNotFoundException", (
        f"DescribeKeyValueStore on a never-existed ARN returned {never_code!r}, expected "
        f"'ResourceNotFoundException'; without this contrast the ConflictException above says "
        f"nothing about deletion"
    )
    expected_message = "No such Key-Value-Store exists"
    assert never_message == expected_message, f"expected the message {expected_message!r}, got {never_message!r}"

    # Positive control: the sibling store still serves the data plane.
    alive = survivor["arn"]
    live_etag = kvs.describe_key_value_store(KvsARN=alive)["ETag"]
    put = kvs.put_key(KvsARN=alive, Key="survivor-key", Value="v", IfMatch=live_etag)
    assert put["ItemCount"] == 1, (
        f"the surviving store stopped accepting writes after its sibling was deleted: "
        f"ItemCount {put['ItemCount']!r}"
    )
    assert kvs.get_key(KvsARN=alive, Key="survivor-key")["Value"] == "v", (
        "the surviving store cannot read back a key it just accepted; the errors above were "
        "therefore about the account's data plane, not about the deleted store"
    )
    assert [i["Key"] for i in kvs.list_keys(KvsARN=alive, MaxResults=50)["Items"]] == [
        "survivor-key"
    ], "ListKeys on the surviving store does not report the key it just accepted"
    assert kvs.delete_key(KvsARN=alive, Key="survivor-key", IfMatch=put["ETag"])["ItemCount"] == 0, (
        "DeleteKey on the surviving store did not empty it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
