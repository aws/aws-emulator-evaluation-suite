"""access-point-alias-and-endpoints-survive-policy-churn."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-alias-and-endpoints-survive-policy-churn"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c1", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """The alias minted by CreateAccessPoint is the same string Get/ListAccessPoints report later,
    survives attaching and detaching a policy, and leaves the listing only on delete.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-apid-")
    name = ctx.unique_name("sim2real-behav-apid-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    created = s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    alias = created["Alias"]
    arn = created["AccessPointArn"]
    assert arn == f"arn:aws:s3:{ctx.region}:{account}:accesspoint/{name}", (
        f"CreateAccessPoint minted arn {arn!r}, not the documented accesspoint/<name> form"
    )
    assert alias.endswith("-s3alias"), (
        f"alias {alias!r} does not carry the reserved -s3alias suffix"
    )
    assert alias.startswith(name[:20]), (
        f"alias {alias!r} is not derived from the access point name {name!r}"
    )

    got = s3c.get_access_point(AccountId=account, Name=name)
    assert got["Alias"] == alias, (
        f"GetAccessPoint reported alias {got['Alias']!r}, CreateAccessPoint minted {alias!r}"
    )
    assert got["Bucket"] == bucket, f"GetAccessPoint reported bucket {got['Bucket']!r}"
    assert got["BucketAccountId"] == account, (
        f"GetAccessPoint reported BucketAccountId {got['BucketAccountId']!r}"
    )
    assert got["NetworkOrigin"] == "Internet", (
        f"an access point created with no VpcConfiguration reported NetworkOrigin "
        f"{got['NetworkOrigin']!r}, expected Internet"
    )
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", got["Endpoints"]["ipv4"]), (
        f"GetAccessPoint reported ipv4 endpoint {got['Endpoints']['ipv4']!r}"
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "s3:GetObject",
                "Resource": f"{arn}/object/*",
            }
        ],
    }
    s3c.put_access_point_policy(AccountId=account, Name=name, Policy=json.dumps(policy))
    s3c.delete_access_point_policy(AccountId=account, Name=name)
    after = s3c.get_access_point(AccountId=account, Name=name)
    assert (after["Alias"], after["AccessPointArn"]) == (alias, arn), (
        f"identity moved across policy churn: alias/arn were {(alias, arn)!r}, "
        f"now {(after['Alias'], after['AccessPointArn'])!r}"
    )

    listed = {
        ap["Name"]: ap["Alias"] for ap in _all_access_points(s3c, account) if "Alias" in ap
    }
    assert listed.get(name) == alias, (
        f"ListAccessPoints reported alias {listed.get(name)!r} for {name!r}, expected {alias!r}"
    )

    s3c.delete_access_point(AccountId=account, Name=name)
    remaining = [ap["Name"] for ap in _all_access_points(s3c, account)]
    assert name not in remaining, (
        f"{name!r} is still in ListAccessPoints after DeleteAccessPoint: {remaining!r}"
    )
    code, code_msg = _error(lambda: s3c.get_access_point(AccountId=account, Name=name))
    assert code == "NoSuchAccessPoint", (
        f"GetAccessPoint on the deleted access point returned {code!r}, expected NoSuchAccessPoint"
    )
    code_want = "The specified accesspoint does not exist"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )
    code, code_msg = _error(
        lambda: s3c.put_access_point_policy(
            AccountId=account, Name=name, Policy=json.dumps(policy)
        )
    )
    assert code == "NoSuchAccessPoint", (
        f"PutAccessPointPolicy on the deleted access point returned {code!r}, "
        f"expected NoSuchAccessPoint — a mutation must not resurrect a dead id"
    )
    code_want = "The specified accesspoint does not exist"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )



def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _all_access_points(s3c, account: str, **kw) -> list:
    """Every access point in the account, following pagination beyond page 1."""
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
