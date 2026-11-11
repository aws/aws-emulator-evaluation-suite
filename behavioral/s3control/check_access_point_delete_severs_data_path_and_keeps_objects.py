"""access-point-delete-severs-data-path-and-keeps-objects."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-delete-severs-data-path-and-keeps-objects"
GROUP = "state-machine"
SERVICES = ["s3control"]
#: Upper bound for one post-delete convergence wait.
POLL_BUDGET_S = 230.0


@tags("cap:c1", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """Deleting an in-use access point severs reads through it while the object stays readable on the
    bucket, a second delete is refused with NoSuchAccessPoint, and the name can be re-created.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.account
    bucket = ctx.unique_name("sim2real-behav-apdel-")
    name = ctx.unique_name("sim2real-behav-apdel-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="keep/me.txt", Body=b"survives-the-delete")

    ap_arn = s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)[
        "AccessPointArn"
    ]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    want_arn = f"arn:aws:s3:{ctx.region}:{account}:accesspoint/{name}"
    assert ap_arn == want_arn, f"CreateAccessPoint returned arn {ap_arn!r}, expected {want_arn!r}"
    got_bucket = s3c.get_access_point(AccountId=account, Name=name)["Bucket"]
    assert got_bucket == bucket, f"GetAccessPoint names bucket {got_bucket!r}, expected {bucket!r}"

    through_ap = s3.get_object(Bucket=ap_arn, Key="keep/me.txt")["Body"].read()
    assert through_ap == b"survives-the-delete", (
        f"the access point read returned {through_ap!r} before the delete"
    )

    s3c.delete_access_point(AccountId=account, Name=name)

    # Beat 1: GetAccessPoint by name converges to NoSuchAccessPoint (bounded convergence).
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            s3c.get_access_point(AccountId=account, Name=name)
        except ClientError as exc:
            _assert_error(exc.response, "GetAccessPoint after delete", "NoSuchAccessPoint", 404)
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"GetAccessPoint still serves the deleted access point after {POLL_BUDGET_S:.0f}s")
        time.sleep(2)

    # Beat 2: the bucket's access point listing no longer names it.
    listed = _access_point_names(s3c, account, bucket)
    assert name not in listed, f"ListAccessPoints(Bucket) still lists the deleted access point: {listed!r}"

    # Beat 3: the data path through the ARN converges to NoSuchAccessPoint (a 4xx), and a second
    # delete refuses with NoSuchAccessPoint 404.
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            s3.get_object(Bucket=ap_arn, Key="keep/me.txt")
        except ClientError as exc:
            _assert_error(exc.response, "GetObject through the deleted access point", "NoSuchAccessPoint", None)
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"GetObject through the deleted access point still served after {POLL_BUDGET_S:.0f}s")
        time.sleep(2)
    refused = _err(lambda: s3c.delete_access_point(AccountId=account, Name=name))
    _assert_error(
        refused,
        "DeleteAccessPoint on the deleted access point", "NoSuchAccessPoint", 404,
    )
    expected_message = "The specified accesspoint does not exist"
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'

    direct = s3.get_object(Bucket=bucket, Key="keep/me.txt")["Body"].read()
    assert direct == b"survives-the-delete", (
        f"deleting the access point damaged the object: direct read gave {direct!r}"
    )
    keys = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
            for o in page.get("Contents", [])]
    assert keys == ["keep/me.txt"], f"bucket contents after the delete were {keys!r}"

    # The name is released, not tombstoned: the same name can be bound again.
    again = s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    assert again["AccessPointArn"] == ap_arn, (
        f"re-creating the deleted name minted arn {again['AccessPointArn']!r}, "
        f"expected the deterministic {ap_arn!r}"
    )

    revived = s3.get_object(Bucket=again["AccessPointArn"], Key="keep/me.txt")["Body"].read()
    assert revived == b"survives-the-delete", (
        f"the re-created access point read returned {revived!r}, expected the object to be "
        f"reachable through the revived name"
    )



def _err(fn):
    """Call fn(); return the ClientError response it raises. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_error(resp, what, code, status):
    """Grade a refusal on code + HTTP status (any 4xx when status is None) + non-empty message."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"{what}: expected {code}, got {err.get('Code')!r}"
    if status is None:
        assert isinstance(got_status, int) and 400 <= got_status < 500, f"{what}: expected a 4xx, got {got_status!r}"
    else:
        assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
    assert err.get("Message"), f"{what}: expected a non-empty error message, got {err.get('Message')!r}"


def _drop_access_point(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessPoint":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)


def _access_point_names(s3c, account: str, bucket: str) -> list:
    """Every access point name on ``bucket``; ListAccessPoints has no botocore paginator, so NextToken is followed."""
    names: list = []
    kwargs = {"AccountId": account, "Bucket": bucket}
    while True:
        page = s3c.list_access_points(**kwargs)
        names.extend(ap["Name"] for ap in page.get("AccessPointList", []))
        token = page.get("NextToken")
        if not token:
            return names
        kwargs["NextToken"] = token


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
