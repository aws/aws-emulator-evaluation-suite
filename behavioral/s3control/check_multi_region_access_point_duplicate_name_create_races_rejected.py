"""multi-region-access-point-duplicate-name-create-races-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multi-region-access-point-duplicate-name-create-races-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]

_POLL_TIMEOUT_S = 1500
_POLL_INTERVAL_S = 2


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent same-name MRAP creates are both accepted; one settles SUCCEEDED, the other
    FAILED with MultiRegionAccessPointAlreadyOwnedByYou, leaving exactly one access point,
    while a create under a free name succeeds cleanly."""
    account = ctx.account
    s3_west = ctx.client("s3", region="us-west-2")
    s3_east = ctx.client("s3", region="us-east-1")
    s3c = ctx.client("s3control", region="us-west-2")

    bucket_west = ctx.unique_name("sim2real-behav-mrapdupw-")
    bucket_east = ctx.unique_name("sim2real-behav-mrapdupe-")
    contested_name = ctx.unique_name("sim2real-behav-mrapdup-")
    control_name = ctx.unique_name("sim2real-behav-mrapctl-")

    _create_bucket(s3_west, bucket_west, "us-west-2")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3_west, bucket_west))
    _create_bucket(s3_east, bucket_east, "us-east-1")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3_east, bucket_east))
    # Registered before both delete submits, so it runs after them and waits for both at once.
    delete_tokens: list = []
    ctx.on_cleanup(lambda: _await_mrap_deletes(s3c, account, delete_tokens))

    def _create(name: str) -> str:
        return s3c.create_multi_region_access_point(
            AccountId=account,
            Details={
                "Name": name,
                "Regions": [{"Bucket": bucket_west}, {"Bucket": bucket_east}],
            },
        )["RequestTokenARN"]

    def _accepted(fut) -> str:
        try:
            return fut.result()
        except ClientError as exc:
            raise AssertionError(
                "a concurrent CreateMultiRegionAccessPoint under a contested name was rejected "
                f"synchronously with {exc.response['Error']!r}; both creates must be accepted and "
                "the conflict reported by the losing asynchronous operation"
            ) from exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_create, contested_name)
        fut_b = pool.submit(_create, contested_name)
        ctx.on_cleanup(lambda: _submit_mrap_delete(s3c, account, contested_name, delete_tokens))
        token_a, token_b = _accepted(fut_a), _accepted(fut_b)

    assert token_a != token_b, (
        "two concurrent CreateMultiRegionAccessPoint calls under the same name returned the "
        "SAME request token — they were not treated as two independent operations"
    )

    op_a = _poll_operation(ctx, s3c, account, token_a, _POLL_TIMEOUT_S)
    op_b = _poll_operation(ctx, s3c, account, token_b, _POLL_TIMEOUT_S)
    statuses = {token_a: op_a["RequestStatus"], token_b: op_b["RequestStatus"]}
    succeeded = [t for t, s in statuses.items() if s == "SUCCEEDED"]
    failed = [t for t, s in statuses.items() if s == "FAILED"]
    assert len(succeeded) == 1 and len(failed) == 1, (
        f"two concurrent creates under the same name settled into {statuses!r}, expected "
        "exactly one SUCCEEDED and one FAILED"
    )
    failed_op = op_a if op_a["RequestStatus"] == "FAILED" else op_b
    error_code = failed_op.get("ResponseDetails", {}).get("ErrorDetails", {}).get("Code")
    assert error_code == "MultiRegionAccessPointAlreadyOwnedByYou", (
        f"the losing concurrent create failed with {error_code!r}, expected "
        "MultiRegionAccessPointAlreadyOwnedByYou"
    )

    got = s3c.get_multi_region_access_point(AccountId=account, Name=contested_name)["AccessPoint"]
    assert got["Status"] in ("CREATING", "READY"), (
        f"after the race settled, the access point under the contested name reports status "
        f"{got['Status']!r}, expected it to be converging to or already READY"
    )
    matches = [ap for ap in _all_mraps(s3c, account) if ap["Name"] == contested_name]
    assert len(matches) == 1, (
        f"ListMultiRegionAccessPoints holds {len(matches)} entries named {contested_name!r} "
        "after the race — the loser must not have left a second one behind"
    )

    # Positive control: the identical request under a free name has no conflict to race against.
    control_token = _create(control_name)
    ctx.on_cleanup(lambda: _submit_mrap_delete(s3c, account, control_name, delete_tokens))
    control_op = _poll_operation(ctx, s3c, account, control_token, _POLL_TIMEOUT_S)
    assert control_op["RequestStatus"] == "SUCCEEDED", (
        f"the control create under a free name settled into {control_op['RequestStatus']!r}, "
        "expected SUCCEEDED with no competing operation"
    )


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_operation(ctx, s3c, account: str, token: str, timeout_s: float) -> dict:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        op = s3c.describe_multi_region_access_point_operation(
            AccountId=account, RequestTokenARN=token
        )["AsyncOperation"]
        if op["RequestStatus"] in ("SUCCEEDED", "FAILED"):
            return op
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"MRAP operation {token!r} to settle: the run budget ended first; not graded")
            raise AssertionError(
                f"MRAP operation {token!r} did not settle to SUCCEEDED or FAILED within "
                f"{timeout_s:.0f}s; last status {op['RequestStatus']!r}"
            )
        time.sleep(_POLL_INTERVAL_S)


def _all_mraps(s3c, account: str) -> list:
    out: list = []
    token = None
    while True:
        args = {"AccountId": account}
        if token:
            args["NextToken"] = token
        page = s3c.list_multi_region_access_points(**args)
        out.extend(page.get("AccessPoints", []))
        token = page.get("NextToken")
        if not token:
            return out


def _submit_mrap_delete(s3c, account: str, name: str, tokens: list) -> None:
    """Submit the async delete and record its request token; an absent access point is done."""
    try:
        s3c.get_multi_region_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchMultiRegionAccessPoint":
            raise
        return
    tokens.append(s3c.delete_multi_region_access_point(
        AccountId=account, Details={"Name": name}
    )["RequestTokenARN"])


def _await_mrap_deletes(s3c, account: str, tokens: list, timeout_s: float = 840) -> None:
    """Wait for every submitted delete to succeed under one deadline inside the cleanup budget;
    FAILED or the deadline raises."""
    deadline = time.monotonic() + timeout_s
    pending = list(tokens)
    while True:
        for token in list(pending):
            op = s3c.describe_multi_region_access_point_operation(
                AccountId=account, RequestTokenARN=token
            )["AsyncOperation"]
            if op["RequestStatus"] == "SUCCEEDED":
                pending.remove(token)
            elif op["RequestStatus"] == "FAILED" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"teardown: Multi-Region Access Point delete {token!r} ended "
                    f"{op['RequestStatus']!r}; ResponseDetails={op.get('ResponseDetails')!r}"
                )
        if not pending:
            return
        time.sleep(_POLL_INTERVAL_S)


def _create_bucket(s3, name: str, region: str) -> None:
    params: dict = {"Bucket": name}
    if region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
