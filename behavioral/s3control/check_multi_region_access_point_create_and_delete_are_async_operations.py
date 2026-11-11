"""multi-region-access-point-create-and-delete-are-async-operations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multi-region-access-point-create-and-delete-are-async-operations"
GROUP = "state-machine"
SERVICES = ["s3control"]

_CREATE_POLL_TIMEOUT_S = 1500
_DELETE_POLL_TIMEOUT_S = 900
_POLL_INTERVAL_S = 2


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/DeleteMultiRegionAccessPoint return a request token naming an async operation that
    settles SUCCEEDED; the MRAP reports READY with both regions only after create finishes,
    and delete is the same asynchronous handoff."""
    account = ctx.account
    s3_west = ctx.client("s3", region="us-west-2")
    s3_east = ctx.client("s3", region="us-east-1")
    s3c = ctx.client("s3control", region="us-west-2")

    bucket_west = ctx.unique_name("sim2real-behav-mrapw-")
    bucket_east = ctx.unique_name("sim2real-behav-mrape-")
    mrap_name = ctx.unique_name("sim2real-behav-mrap-")

    _create_bucket(s3_west, bucket_west, "us-west-2")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3_west, bucket_west))
    _create_bucket(s3_east, bucket_east, "us-east-1")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3_east, bucket_east))

    created = s3c.create_multi_region_access_point(
        AccountId=account,
        Details={
            "Name": mrap_name,
            "Regions": [{"Bucket": bucket_west}, {"Bucket": bucket_east}],
        },
    )
    create_token = created["RequestTokenARN"]
    ctx.on_cleanup(lambda: _drop_mrap(s3c, account, mrap_name))
    assert create_token.startswith(f"arn:aws:s3:us-west-2:{account}:async-request/mrap/create/"), (
        f"CreateMultiRegionAccessPoint returned token {create_token!r}, expected an "
        "async-request/mrap/create ARN naming this operation"
    )

    create_op = _poll_operation(s3c, account, create_token, _CREATE_POLL_TIMEOUT_S)
    assert create_op["RequestStatus"] == "SUCCEEDED", (
        f"the create operation settled into {create_op['RequestStatus']!r} within "
        f"{_CREATE_POLL_TIMEOUT_S}s, expected SUCCEEDED; ResponseDetails="
        f"{create_op.get('ResponseDetails')!r}"
    )
    assert create_op["Operation"] == "CreateMultiRegionAccessPoint", (
        f"DescribeMultiRegionAccessPointOperation named the operation "
        f"{create_op['Operation']!r} for a create's own token"
    )

    got = s3c.get_multi_region_access_point(AccountId=account, Name=mrap_name)["AccessPoint"]
    assert got["Status"] == "READY", (
        f"GetMultiRegionAccessPoint reports status {got['Status']!r} after the create "
        "operation SUCCEEDED, expected READY"
    )
    regions = {(r["Bucket"], r["Region"]) for r in got["Regions"]}
    assert regions == {(bucket_west, "us-west-2"), (bucket_east, "us-east-1")}, (
        f"GetMultiRegionAccessPoint lists regions {sorted(regions)}, expected both member "
        f"buckets: {sorted({(bucket_west, 'us-west-2'), (bucket_east, 'us-east-1')})}"
    )

    deleted = s3c.delete_multi_region_access_point(AccountId=account, Details={"Name": mrap_name})
    delete_token = deleted["RequestTokenARN"]
    assert delete_token.startswith(f"arn:aws:s3:us-west-2:{account}:async-request/mrap/delete/"), (
        f"DeleteMultiRegionAccessPoint returned token {delete_token!r}, expected an "
        "async-request/mrap/delete ARN naming this operation"
    )
    assert delete_token != create_token, (
        "the delete handed back the SAME request token as the create — it is not naming its "
        "own operation"
    )

    delete_op = _poll_operation(s3c, account, delete_token, _DELETE_POLL_TIMEOUT_S)
    assert delete_op["RequestStatus"] == "SUCCEEDED", (
        f"the delete operation settled into {delete_op['RequestStatus']!r} within "
        f"{_DELETE_POLL_TIMEOUT_S}s, expected SUCCEEDED; ResponseDetails="
        f"{delete_op.get('ResponseDetails')!r}"
    )
    assert delete_op["Operation"] == "DeleteMultiRegionAccessPoint", (
        f"DescribeMultiRegionAccessPointOperation named the operation "
        f"{delete_op['Operation']!r} for a delete's own token"
    )

    code, message = _error(lambda: s3c.get_multi_region_access_point(AccountId=account, Name=mrap_name))
    assert code == "NoSuchMultiRegionAccessPoint", (
        f"GetMultiRegionAccessPoint after the delete SUCCEEDED returned {code!r}, expected "
        "NoSuchMultiRegionAccessPoint — the access point must actually be gone"
    )
    expected_message = "The specified Multi-Region Access Point does not exist."
    assert message == expected_message, (
        f"the not-found refusal should read {expected_message!r}, got {message!r}"
    )


# ===== helpers =====

def _poll_operation(s3c, account: str, token: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = s3c.describe_multi_region_access_point_operation(
            AccountId=account, RequestTokenARN=token
        )["AsyncOperation"]
        if op["RequestStatus"] in ("SUCCEEDED", "FAILED"):
            return op
        time.sleep(_POLL_INTERVAL_S)
    assert op is not None, "DescribeMultiRegionAccessPointOperation never returned anything"
    return op


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("call unexpectedly succeeded; an error code was expected")


def _drop_mrap(s3c, account: str, name: str, timeout_s: float = 840) -> None:
    """Submit the async delete and wait for it to succeed; anything but SUCCEEDED or an absent
    access point raises."""
    try:
        s3c.get_multi_region_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchMultiRegionAccessPoint":
            raise
        return
    token = s3c.delete_multi_region_access_point(
        AccountId=account, Details={"Name": name}
    )["RequestTokenARN"]
    deadline = time.monotonic() + timeout_s
    while True:
        op = s3c.describe_multi_region_access_point_operation(
            AccountId=account, RequestTokenARN=token
        )["AsyncOperation"]
        if op["RequestStatus"] == "SUCCEEDED":
            return
        if op["RequestStatus"] == "FAILED" or time.monotonic() >= deadline:
            raise AssertionError(
                f"teardown: deleting Multi-Region Access Point {name!r} ended {op['RequestStatus']!r}; "
                f"ResponseDetails={op.get('ResponseDetails')!r}"
            )
        time.sleep(_POLL_INTERVAL_S)


def _create_bucket(s3, name: str, region: str) -> None:
    params: dict = {"Bucket": name}
    if region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Empty and delete one bucket this check created; a teardown failure raises."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
