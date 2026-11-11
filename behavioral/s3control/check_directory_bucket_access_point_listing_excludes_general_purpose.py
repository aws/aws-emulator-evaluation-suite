"""directory-bucket-access-point-listing-excludes-general-purpose."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "directory-bucket-access-point-listing-excludes-general-purpose"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c2", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """General-purpose access points appear in ListAccessPoints but never in
    ListAccessPointsForDirectoryBuckets, which stays stable as a second one is added."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-dirls-")
    first = ctx.unique_name("sim2real-behav-dls1-")
    second = ctx.unique_name("sim2real-behav-dls2-")

    baseline = {ap["Name"] for ap in _all_directory_access_points(s3c, account)}

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3c.create_access_point(AccountId=account, Name=first, Bucket=bucket)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, first))

    general = {ap["Name"] for ap in _all_access_points(s3c, account)}
    assert first in general, (
        f"{first!r} is missing from ListAccessPoints: {sorted(general)!r}"
    )
    directory = {ap["Name"] for ap in _all_directory_access_points(s3c, account)}
    assert first not in directory, (
        f"the general-purpose access point {first!r} appeared in "
        f"ListAccessPointsForDirectoryBuckets: {sorted(directory)!r}"
    )
    assert directory == baseline, (
        f"creating a general-purpose access point changed the directory-bucket listing from "
        f"{sorted(baseline)!r} to {sorted(directory)!r}"
    )

    s3c.create_access_point(AccountId=account, Name=second, Bucket=bucket)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, second))
    general = {ap["Name"] for ap in _all_access_points(s3c, account)}
    assert {first, second} <= general, (
        f"ListAccessPoints is missing one of the two access points: {sorted(general)!r}"
    )
    directory = {ap["Name"] for ap in _all_directory_access_points(s3c, account)}
    assert directory == baseline, (
        f"a second general-purpose access point changed the directory-bucket listing to "
        f"{sorted(directory)!r}"
    )

    s3c.delete_access_point(AccountId=account, Name=second)
    assert second not in {ap["Name"] for ap in _all_access_points(s3c, account)}, (
        f"{second!r} survived DeleteAccessPoint in the general-purpose listing"
    )
    gone_code, gone_code_msg = _error(lambda: s3c.get_access_point(AccountId=account, Name=second))
    assert gone_code == "NoSuchAccessPoint", (
        f"GetAccessPoint on the deleted {second!r} returned {gone_code!r}, "
        "expected NoSuchAccessPoint"
    )
    gone_code_want = "The specified accesspoint does not exist"
    assert gone_code_msg == gone_code_want, (
        f"the refusal carried message {gone_code_msg!r}, expected {gone_code_want!r}"
    )
    assert {ap["Name"] for ap in _all_directory_access_points(s3c, account)} == baseline, (
        "deleting a general-purpose access point perturbed the directory-bucket listing"
    )


# ===== helpers =====

def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _all_access_points(s3c, account: str, **kw) -> list:
    out: list = []
    token = None
    while True:
        args = dict(AccountId=account, **kw)
        if token:
            args["NextToken"] = token
        page = s3c.list_access_points(**args)
        out.extend(page.get("AccessPointList", []))
        token = page.get("NextToken")
        if not token:
            return out


def _all_directory_access_points(s3c, account: str) -> list:
    out: list = []
    token = None
    while True:
        args = {"AccountId": account}
        if token:
            args["NextToken"] = token
        page = s3c.list_access_points_for_directory_buckets(**args)
        out.extend(page.get("AccessPointList", []))
        token = page.get("NextToken")
        if not token:
            return out


def _drop_access_point(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessPoint":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
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
