"""harvest-job-list-filters-reflect-status."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "harvest-job-list-filters-reflect-status"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHarvestJobs' IncludeStatus is a real filter: a new HarvestJob is listed only under the status
    DescribeHarvestJob reports on both sides of the three lists, and IncludeChannelId with
    IncludeStatus together is UnprocessableEntityException."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(
        Id=endpoint_id, ChannelId=channel_id, HlsPackage={}, StartoverWindowSeconds=86400
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    infra = _create_harvest_infra(ctx)
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=10)
    end = now - timedelta(minutes=5)

    job_id = ctx.unique_name("sim2real-mp-hj-")
    created = _create_harvest_job_with_retry(
        mp,
        Id=job_id,
        OriginEndpointId=endpoint_id,
        StartTime=start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        EndTime=end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        S3Destination={
            "BucketName": infra["bucket"],
            "ManifestKey": "harvested/index.m3u8",
            "RoleArn": infra["role_arn"],
        },
    )
    assert created["Status"] == "IN_PROGRESS"
    assert created["ChannelId"] == channel_id

    _assert_listed_under_held_status(ctx, mp, job_id)

    # The two filters are mutually exclusive, and saying so is part of the contract: real AWS
    # refuses the combination outright rather than intersecting them.
    both_code, both_message = _error_code_and_message(
        lambda: mp.list_harvest_jobs(IncludeChannelId=channel_id, IncludeStatus="IN_PROGRESS")
    )
    assert both_code == "UnprocessableEntityException", (
        f"expected ListHarvestJobs to refuse IncludeChannelId+IncludeStatus together, got {both_code!r}"
    )
    assert both_message == "includeStatus cannot be specified at the same time as IncludeChannelId", (
        f"expected the exact UnprocessableEntityException message AWS returns, got {both_message!r}"
    )
    assert "same time" in both_message, (
        f"expected the refusal to name the mutual exclusion, got {both_message!r}"
    )


# ===== helpers =====
_STATUSES = ("IN_PROGRESS", "SUCCEEDED", "FAILED")


def _assert_listed_under_held_status(ctx, mp, job_id, timeout_s=120.0, interval_s=5.0):
    """The job is listed under the status DescribeHarvestJob reports before and after the three
    IncludeStatus lists, and under no other. The job moves from IN_PROGRESS to a terminal status
    on its own, so a pass where the status changed mid-way, or the listing has not yet caught up
    with it, repeats until the deadline; the last mismatch raises."""
    deadline = time.monotonic() + min(timeout_s, ctx.time_left() or timeout_s)
    while True:
        before = mp.describe_harvest_job(Id=job_id)["Status"]
        assert before in _STATUSES, f"DescribeHarvestJob reported an undocumented status {before!r}"
        listed = {status: job_id in _list_job_ids(mp, status) for status in _STATUSES}
        after = mp.describe_harvest_job(Id=job_id)["Status"]
        expected = {status: status == before for status in _STATUSES}
        if after == before and listed == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected {job_id} listed only under IncludeStatus={before} while DescribeHarvestJob "
                f"held {before} (after the lists: {after}); listed under: "
                f"{sorted(s for s, hit in listed.items() if hit)}"
            )
        time.sleep(interval_s)


def _create_harvest_job_with_retry(mp, timeout_s=90.0, **kwargs):
    """IAM role trust can take a few seconds to propagate; retry while MediaPackage
    reports the role as not yet assumable (either ForbiddenException or an
    UnprocessableEntityException whose message names assumability)."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return mp.create_harvest_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ForbiddenException" or (
                code == "UnprocessableEntityException" and "assumable" in message.lower()
            ):
                last_exc = e
                time.sleep(5)
                continue
            raise
    raise last_exc


def _list_job_ids(mp, status: str) -> set[str]:
    """Every HarvestJob id ListHarvestJobs reports for *status*.

    IncludeStatus ONLY: passing
    IncludeChannelId alongside it is refused with UnprocessableEntityException, "includeStatus
    cannot be specified at the same time as IncludeChannelId" -- which the check asserts directly
    rather than working around.
    """
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"IncludeStatus": status}
        if token:
            kwargs["NextToken"] = token
        resp = mp.list_harvest_jobs(**kwargs)
        ids.update(j["Id"] for j in resp.get("HarvestJobs", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _error_code_and_message(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises: a target that
    ACCEPTS a call real AWS refuses must not pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _create_harvest_infra(ctx) -> dict[str, str]:
    """Provisions a real S3 bucket + IAM role that MediaPackage can assume to write
    harvested output, so CreateHarvestJob sees a well-formed, real S3Destination."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-mp-harvest-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-mp-harvest-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapackage.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="harvest-s3-write", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="harvest-s3-write")
    )
    return {"bucket": bucket, "role_arn": role_arn}


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
