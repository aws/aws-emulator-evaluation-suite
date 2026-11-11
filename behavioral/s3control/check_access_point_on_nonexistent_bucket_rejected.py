"""access-point-on-nonexistent-bucket-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-on-nonexistent-bucket-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccessPoint on a missing or just-deleted bucket is refused and leaves no access point
    in ListAccessPoints or GetAccessPoint, while the identical request on a live bucket succeeds.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    live = ctx.unique_name("sim2real-behav-apnb-")
    ghost = ctx.unique_name("sim2real-behav-apghost-")
    name = ctx.unique_name("sim2real-behav-apnb-")

    _create_bucket(ctx, s3, live)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, live))

    code, code_msg = _error(
        lambda: s3c.create_access_point(AccountId=account, Name=name, Bucket=ghost)
    )
    assert code == "InvalidRequest", (
        f"CreateAccessPoint against a bucket that was never created returned {code!r}, "
        "expected InvalidRequest"
    )
    code_want = "Amazon S3 AccessPoint can only be created for existing bucket"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )

    # Effect absent: nothing was recorded under that name.
    listed = [ap["Name"] for ap in _all_access_points(s3c, account)]
    assert name not in listed, (
        f"the rejected create still registered {name!r}: ListAccessPoints returned {listed!r}"
    )
    get_code, get_code_msg = _error(lambda: s3c.get_access_point(AccountId=account, Name=name))
    assert get_code == "NoSuchAccessPoint", (
        f"GetAccessPoint after the rejected create returned {get_code!r}, "
        "expected NoSuchAccessPoint"
    )
    get_code_want = "The specified accesspoint does not exist"
    assert get_code_msg == get_code_want, (
        f"the refusal carried message {get_code_msg!r}, expected {get_code_want!r}"
    )

    # A bucket that existed and was deleted is rejected identically — the validation reads
    # live state, not a create-time cache.
    recently_deleted = ctx.unique_name("sim2real-behav-apgone-")
    _create_bucket(ctx, s3, recently_deleted)
    s3.delete_bucket(Bucket=recently_deleted)
    gone_code, gone_code_msg = _error(
        lambda: s3c.create_access_point(AccountId=account, Name=name, Bucket=recently_deleted)
    )
    assert gone_code == "InvalidRequest", (
        f"CreateAccessPoint against a just-deleted bucket returned {gone_code!r}, "
        "expected InvalidRequest"
    )
    gone_code_want = "Amazon S3 AccessPoint can only be created for existing bucket"
    assert gone_code_msg == gone_code_want, (
        f"the refusal carried message {gone_code_msg!r}, expected {gone_code_want!r}"
    )

    # Positive control: the same name against the live bucket is accepted.
    created = s3c.create_access_point(AccountId=account, Name=name, Bucket=live)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    assert created["AccessPointArn"].endswith(f"accesspoint/{name}"), (
        f"the control create returned arn {created['AccessPointArn']!r}"
    )
    assert s3c.get_access_point(AccountId=account, Name=name)["Bucket"] == live, (
        "the control access point does not serve the live bucket"
    )


# ===== helpers =====

def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
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
