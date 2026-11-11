"""access-point-scope-does-not-answer-for-general-purpose-access-point-rejected."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-scope-does-not-answer-for-general-purpose-access-point-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]

#: The scope Permissions enum, from the s3control Smithy model. Sent as INPUT, never used as an
#: accept-set for an answer.
_SCOPE = {
    "Prefixes": ["allowed/"],
    "Permissions": ["GetObject", "ListBucket"],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Put/Get/DeleteAccessPointScope refuse a general-purpose access point with one shared 4xx code,
    before, while and after it exists, leaving its record and policy untouched.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-apscp-")
    name = ctx.unique_name("sim2real-behav-apsp-")

    for operation in ("put_access_point_scope", "get_access_point_scope",
                      "delete_access_point_scope"):
        assert hasattr(s3c, operation), (
            f"the s3control client does not expose {operation!r}; this check needs a botocore "
            "carrying the access point scope operations (present in 1.43.94)"
        )

    # Scope lives on the directory-bucket access point surface, whose access points exist only in
    # Dedicated Local Zones, so only the refusal for a general-purpose name is observable here.
    probes = {
        "PutAccessPointScope":
            lambda: s3c.put_access_point_scope(AccountId=account, Name=name, Scope=_SCOPE),
        "GetAccessPointScope":
            lambda: s3c.get_access_point_scope(AccountId=account, Name=name),
        "DeleteAccessPointScope":
            lambda: s3c.delete_access_point_scope(AccountId=account, Name=name),
    }

    # Leg 1 — the scope surface's answer BEFORE the general-purpose name exists at all.
    before = {operation: _refusal(call) for operation, call in probes.items()}

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    ap_arn = s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)[
        "AccessPointArn"
    ]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))

    # Positive control. The name resolves in the general-purpose namespace, AND the account can
    # restrict this very access point through that namespace's own restriction operation. Without
    # this beat, "scope is refused" is indistinguishable from "every call is refused".
    resolved = s3c.get_access_point(AccountId=account, Name=name)
    assert resolved["Bucket"] == bucket, (
        f"GetAccessPoint reports {name!r} fronting {resolved.get('Bucket')!r}, expected {bucket!r}"
    )
    listed = [ap["Name"] for ap in _all_access_points(s3c, account)]
    assert name in listed, f"{name!r} is missing from ListAccessPoints: {listed!r}"
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "s3:GetObject",
                "Resource": f"{ap_arn}/object/allowed/*",
            }
        ],
    })
    s3c.put_access_point_policy(AccountId=account, Name=name, Policy=policy)
    ctx.on_cleanup(lambda: _drop_ap_policy(s3c, account, name))
    stored = json.loads(s3c.get_access_point_policy(AccountId=account, Name=name)["Policy"])
    assert stored == json.loads(policy), (
        f"GetAccessPointPolicy returned {stored!r} for the control policy just written; the "
        "general-purpose restriction path must work or the scope refusals prove nothing"
    )

    # Leg 2 — break exactly one thing: ask the SCOPE surface about a name that demonstrably
    # exists in the general-purpose one.
    during = {operation: _refusal(call) for operation, call in probes.items()}
    codes = {code for code, _ in during.values()}
    by_operation = {op: code for op, (code, _) in during.items()}
    assert len(codes) == 1, (
        f"the three scope operations disagree about a general-purpose access point: "
        f"{by_operation!r}; expected one shared refusal code"
    )
    shared = codes.pop()
    for operation, (code, status) in during.items():
        assert 400 <= status <= 499, (
            f"{operation} on the general-purpose access point {name!r} answered HTTP {status} "
            f"({code!r}); expected a 4xx client error, not a server failure"
        )

    # Effect absent — the refused scope writes did not touch the general-purpose record or the
    # access point policy that the positive control installed.
    after_probe = s3c.get_access_point(AccountId=account, Name=name)
    assert after_probe["AccessPointArn"] == ap_arn, (
        f"the scope probes mutated the access point: ARN is now "
        f"{after_probe['AccessPointArn']!r}, expected {ap_arn!r}"
    )
    survived = json.loads(s3c.get_access_point_policy(AccountId=account, Name=name)["Policy"])
    assert survived == json.loads(policy), (
        f"the refused PutAccessPointScope clobbered the access point policy: it now reads "
        f"{survived!r}, expected {json.loads(policy)!r}"
    )
    directory = [ap["Name"] for ap in _all_directory_access_points(s3c, account)]
    assert name not in directory, (
        f"{name!r} leaked into ListAccessPointsForDirectoryBuckets: {directory!r}; a scope-bearing "
        "listing must not contain a general-purpose access point"
    )

    # Leg 3 — the discriminating invariance. Deleting the general-purpose access point changes
    # what the GENERAL-PURPOSE surface says and must not change what the SCOPE surface says. A
    # target that serves both families from one access point table answers differently before,
    # during and after, because for it the name's existence is what decides.
    s3c.delete_access_point(AccountId=account, Name=name)
    try:
        s3c.get_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        gone = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"GetAccessPoint answered for {name!r} after DeleteAccessPoint")
    assert gone == ("NoSuchAccessPoint", "The specified accesspoint does not exist"), (
        f"GetAccessPoint after DeleteAccessPoint answered {gone!r}, expected NoSuchAccessPoint "
        "with 'The specified accesspoint does not exist'"
    )
    after = {operation: _refusal(call) for operation, call in probes.items()}
    for operation in probes:
        observed = (before[operation][0], during[operation][0], after[operation][0])
        assert observed == (shared, shared, shared), (
            f"{operation} answered {observed!r} before / while / after the general-purpose access "
            f"point {name!r} existed; the scope surface never resolved it, so all three must be "
            f"{shared!r}"
        )



def _refusal(fn) -> tuple:
    """``(error code, http status)`` for ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
        )
    raise AssertionError(
        f"the call succeeded and returned {result!r}; a refusal was expected"
    )


def _all_access_points(s3c, account: str) -> list:
    out: list = []
    token = None
    while True:
        args = {"AccountId": account}
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


def _drop_ap_policy(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point_policy(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchAccessPointPolicy", "NoSuchAccessPoint"):
            raise


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
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )


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
