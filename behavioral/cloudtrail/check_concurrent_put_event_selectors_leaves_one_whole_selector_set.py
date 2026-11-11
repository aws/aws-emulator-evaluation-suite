"""concurrent-put-event-selectors-leaves-one-whole-selector-set."""

from __future__ import annotations

import concurrent.futures
import copy
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-event-selectors-leaves-one-whole-selector-set"
GROUP = 'concurrency'
SERVICES = ['cloudtrail']


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)


def _trail_delivery_policy(bucket, account_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AWSCloudTrailAclCheck", "Effect": "Allow",
             "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
            {"Sid": "AWSCloudTrailWrite", "Effect": "Allow",
             "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject",
             "Resource": [f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                          f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*"],
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ],
    })


def _purge_bucket_once(s3, bucket):
    for pname, list_key, id_key in (("list_objects_v2", "Contents", None),
                                    ("list_object_versions", "Versions", "VersionId"),
                                    ("list_object_versions", "DeleteMarkers", "VersionId")):
        try:
            for page in s3.get_paginator(pname).paginate(Bucket=bucket):
                entries = page.get(list_key, [])
                if not entries:
                    continue
                objects = []
                for entry in entries:
                    item = {"Key": entry["Key"]}
                    if id_key and entry.get(id_key):
                        item["VersionId"] = entry[id_key]
                    objects.append(item)
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            continue


def _drain_and_delete_bucket(s3, bucket, *, attempts=6, delay_s=10.0):
    """Empty and delete the bucket, retrying, and raise on a deadline miss."""
    last = None
    for attempt in range(attempts):
        _purge_bucket_once(s3, bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete bucket {bucket} after {attempts} attempts; a billable S3 bucket has "
        f"been leaked. Last error: {last}"
    )


def _delete_trail(ct, name):
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


# The candidate outcomes in the exact shape GetEventSelectors returns: it always carries
# DataResources and ExcludeManagementEventSources, as [] when unset.
# The baseline differs from both submitted sets, so "both writes were lost" is distinguishable.
_SET_A = [{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True,
           "DataResources": [], "ExcludeManagementEventSources": []}]
_SET_B = [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True,
           "DataResources": [], "ExcludeManagementEventSources": []}]
_BASELINE = [{"ReadWriteType": "All", "IncludeManagementEvents": False,
              "DataResources": [{"Type": "AWS::Lambda::Function",
                                 "Values": ["arn:aws:lambda"]}],
              "ExcludeManagementEventSources": []}]


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutEventSelectors calls with different single-selector sets leave the trail
    holding exactly one submitted set whole: never a merge, a partial, or the prior baseline.
    Which call wins is not asserted, since AWS guarantees no ordering for concurrent writes.
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-ct-conb-").lower()
    _create_bucket_only(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_trail_delivery_policy(bucket, account))

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _call(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    _call(lambda: ct.put_event_selectors(
        TrailName=name, EventSelectors=copy.deepcopy(_BASELINE)))
    established = _call(lambda: ct.get_event_selectors(TrailName=name))["EventSelectors"]
    assert established == _BASELINE, (
        f"the distinctive baseline did not round-trip, so 'both writes were lost' would not be a "
        f"distinguishable outcome: wanted {_BASELINE!r}, got {established!r}"
    )

    def _submit(selectors):
        # Each thread gets its own client: botocore clients are not documented thread-safe.
        client = ctx.client("cloudtrail")
        try:
            client.put_event_selectors(TrailName=name, EventSelectors=copy.deepcopy(selectors))
            return "ok"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_submit, _SET_A), pool.submit(_submit, _SET_B)]
        results = [f.result() for f in futures]

    # Poll until two consecutive reads agree so the result is not measured mid-convergence.
    previous = None
    final = None
    deadline = time.monotonic() + 90
    stable = False
    reads = []
    while time.monotonic() < deadline:
        current = _call(lambda: ct.get_event_selectors(TrailName=name))["EventSelectors"]
        reads.append(current)
        if previous is not None and current == previous:
            final = current
            stable = True
            break
        previous = current
        time.sleep(3)
    assert stable, (
        f"get_event_selectors never returned the same value twice in a row within 90s after the "
        f"two concurrent writes, so the invariant could only have been measured mid-flight. "
        f"Successive reads were {reads!r}"
    )

    assert sum(1 for r in results if r == "ok") >= 1, (
        f"neither concurrent PutEventSelectors succeeded, so nothing was raced and the invariant "
        f"below is vacuous. Per-call outcomes: {results!r}"
    )
    assert len(final) == 1, (
        f"the two single-selector writes were MERGED into {len(final)} selectors: {final!r}. "
        f"PutEventSelectors replaces its argument, it does not append to it -- a target that "
        f"appends silently doubles what a trail collects and bills for."
    )
    assert final in (_SET_A, _SET_B), (
        f"the trail holds a selector set that is neither of the two submitted: {final!r}. "
        f"A={_SET_A!r} B={_SET_B!r}. Per-call outcomes were {results!r}; a blend of the two "
        f"members means a concurrent write was applied field-by-field rather than as a unit."
    )
    assert final != _BASELINE, (
        f"both concurrent writes were lost and the trail still holds its previous set "
        f"{final!r}; at least one call reported success ({results!r}), so a success that did "
        f"not take effect is the defect"
    )
    # The winner is whole in every member, not just in ReadWriteType.
    assert final[0]["DataResources"] == [], (
        f"the winning management-only selector inherited the baseline's data resources: "
        f"{final!r} -- the write was applied as a partial update rather than a replacement"
    )
    assert final[0]["IncludeManagementEvents"] is True, (
        f"the winning selector's IncludeManagementEvents is "
        f"{final[0].get('IncludeManagementEvents')!r}; both submitted sets set it True, so the "
        f"baseline's False survived a replacement that should have overwritten it: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
