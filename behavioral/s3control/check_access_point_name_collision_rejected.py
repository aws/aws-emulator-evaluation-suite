"""access-point-name-collision-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-name-collision-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A duplicate access point name is refused and the first access point survives unchanged
    (same alias and bucket, one listed entry), while the same request under a free name succeeds.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    first_bucket = ctx.unique_name("sim2real-behav-apdup1-")
    second_bucket = ctx.unique_name("sim2real-behav-apdup2-")
    name = ctx.unique_name("sim2real-behav-apdup-")
    other = ctx.unique_name("sim2real-behav-apok-")

    _create_bucket(ctx, s3, first_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, first_bucket))
    _create_bucket(ctx, s3, second_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, second_bucket))

    created = s3c.create_access_point(AccountId=account, Name=name, Bucket=first_bucket)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    alias = created["Alias"]

    code, message = _error_code(
        lambda: s3c.create_access_point(AccountId=account, Name=name, Bucket=second_bucket)
    )
    assert code == "AccessPointAlreadyOwnedByYou", (
        f"re-creating access point {name!r} against a different bucket returned {code!r}, "
        "expected AccessPointAlreadyOwnedByYou"
    )
    want = "Your previous request to create the named accesspoint succeeded and you already own it."
    assert message == want, f"re-creating access point {name!r} said {message!r}, expected {want!r}"

    # The rejected create must not have moved the access point to the second bucket.
    got = s3c.get_access_point(AccountId=account, Name=name)
    assert got["Bucket"] == first_bucket, (
        f"the rejected create re-pointed the access point at {got['Bucket']!r}; "
        f"it must still serve {first_bucket!r}"
    )
    assert got["Alias"] == alias, (
        f"the rejected create re-minted the alias: was {alias!r}, now {got['Alias']!r}"
    )

    matches = [ap for ap in _all_access_points(s3c, account) if ap["Name"] == name]
    assert len(matches) == 1, (
        f"ListAccessPoints holds {len(matches)} entries named {name!r} after the collision"
    )

    # Positive control: the identical request under a free name is accepted.
    ok = s3c.create_access_point(AccountId=account, Name=other, Bucket=second_bucket)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, other))
    assert ok["AccessPointArn"].endswith(f"accesspoint/{other}"), (
        f"the control create returned arn {ok['AccessPointArn']!r}"
    )


# ===== helpers =====

def _error_code(fn):
    """The AWS error (code, message) raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error code was expected")


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
