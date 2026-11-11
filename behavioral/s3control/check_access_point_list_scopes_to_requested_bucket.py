"""access-point-list-scopes-to-requested-bucket."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-list-scopes-to-requested-bucket"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c2", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """ListAccessPoints(Bucket=...) partitions three access points across two buckets by association,
    the unfiltered listing is their union, and a delete removes one from exactly one partition.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket_a = ctx.unique_name("sim2real-behav-aplsa-")
    bucket_b = ctx.unique_name("sim2real-behav-aplsb-")
    ap_a1 = ctx.unique_name("sim2real-behav-apa1-")
    ap_a2 = ctx.unique_name("sim2real-behav-apa2-")
    ap_b1 = ctx.unique_name("sim2real-behav-apb1-")

    _create_bucket(ctx, s3, bucket_a)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_a))
    _create_bucket(ctx, s3, bucket_b)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_b))

    for name, bucket in ((ap_a1, bucket_a), (ap_a2, bucket_a), (ap_b1, bucket_b)):
        s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)
        ctx.on_cleanup(lambda n=name: _drop_access_point(s3c, account, n))

    in_a = {ap["Name"] for ap in _all_access_points(s3c, account, Bucket=bucket_a)}
    assert in_a == {ap_a1, ap_a2}, (
        f"ListAccessPoints(Bucket={bucket_a!r}) returned {sorted(in_a)!r}, "
        f"expected exactly {sorted([ap_a1, ap_a2])!r}"
    )
    in_b = {ap["Name"] for ap in _all_access_points(s3c, account, Bucket=bucket_b)}
    assert in_b == {ap_b1}, (
        f"ListAccessPoints(Bucket={bucket_b!r}) returned {sorted(in_b)!r}, expected [{ap_b1!r}]"
    )

    unfiltered = {ap["Name"] for ap in _all_access_points(s3c, account)}
    assert in_a | in_b <= unfiltered, (
        f"the unfiltered listing {sorted(unfiltered)!r} is missing members of the two partitions"
    )
    buckets = {
        ap["Name"]: ap["Bucket"]
        for ap in _all_access_points(s3c, account)
        if ap["Name"] in (ap_a1, ap_a2, ap_b1)
    }
    assert buckets == {ap_a1: bucket_a, ap_a2: bucket_a, ap_b1: bucket_b}, (
        f"the unfiltered listing reported bucket associations {buckets!r}"
    )

    s3c.delete_access_point(AccountId=account, Name=ap_a2)
    after_a = {ap["Name"] for ap in _all_access_points(s3c, account, Bucket=bucket_a)}
    assert after_a == {ap_a1}, (
        f"after deleting {ap_a2!r}, bucket {bucket_a!r} still lists {sorted(after_a)!r}"
    )
    after_b = {ap["Name"] for ap in _all_access_points(s3c, account, Bucket=bucket_b)}
    assert after_b == {ap_b1}, (
        f"deleting an access point of bucket A changed bucket B's partition to {sorted(after_b)!r}"
    )
    try:
        s3c.get_access_point(AccountId=account, Name=ap_a2)
        raise AssertionError(f"GetAccessPoint({ap_a2!r}) succeeded after delete_access_point")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "NoSuchAccessPoint", (
            f"GetAccessPoint on the deleted access point returned {code!r}, expected NoSuchAccessPoint"
        )
        message = e.response["Error"].get("Message")
        assert message == "The specified accesspoint does not exist", (
            f"GetAccessPoint on the deleted access point carried message {message!r}"
        )



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
