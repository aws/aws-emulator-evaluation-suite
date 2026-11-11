"""delete-workgroup-with-active-queries-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-workgroup-with-active-queries-rejected"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkGroup without RecursiveDeleteOption is rejected with InvalidRequestException for a
    workgroup owning a query execution and leaves it intact, while an empty sibling deletes with
    the same call (positive control) and the busy one deletes once told to recurse."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-athena-del-")
    _create_bucket(ctx, s3, bucket, CHECK)
    output_location = f"s3://{bucket}/results/"

    busy_wg = ctx.unique_name("sim2real-athena-busy-wg-")
    athena.create_work_group(
        Name=busy_wg,
        Configuration={"ResultConfiguration": {"OutputLocation": output_location}},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: athena.delete_work_group(WorkGroup=busy_wg, RecursiveDeleteOption=True)))

    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=busy_wg)[
        "QueryExecutionId"
    ]

    def _terminal():
        qe = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = qe["Status"]["State"]
        return qe if state in ("SUCCEEDED", "FAILED", "CANCELLED") else None

    qe = _poll_until(_terminal, timeout_s=90, interval_s=2)
    assert qe["Status"]["State"] == "SUCCEEDED", f"expected query to succeed, got {qe['Status']['State']}"

    # Break exactly one thing: try to delete a workgroup that owns a query
    # execution without the recursive option.
    code, message = _error(lambda: athena.delete_work_group(WorkGroup=busy_wg))
    assert code == "InvalidRequestException", f"expected delete of busy workgroup to be rejected, got {code}"
    expected = f"WorkGroup {busy_wg} is not empty"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the workgroup and its query execution are both still there.
    wg = athena.get_work_group(WorkGroup=busy_wg)["WorkGroup"]
    assert wg["Name"] == busy_wg, f"expected {busy_wg}, got {wg['Name']}"
    qe_after = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert qe_after["Status"]["State"] == "SUCCEEDED", (
        f"expected query execution to remain SUCCEEDED after rejected delete, got {qe_after['Status']['State']}"
    )

    # Positive control, same call shape: an empty sibling workgroup deletes fine
    # without the recursive option.
    empty_wg = ctx.unique_name("sim2real-athena-empty-wg-")
    athena.create_work_group(Name=empty_wg, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    athena.delete_work_group(WorkGroup=empty_wg)
    code_empty_after, msg_empty_after = _error(lambda: athena.get_work_group(WorkGroup=empty_wg))
    assert code_empty_after == "InvalidRequestException", (
        f"expected empty workgroup to be gone after delete, got {code_empty_after}"
    )
    assert msg_empty_after == "WorkGroup is not found.", msg_empty_after

    # And the busy workgroup deletes cleanly once told to recurse.
    athena.delete_work_group(WorkGroup=busy_wg, RecursiveDeleteOption=True)
    code_busy_after, msg_busy_after = _error(lambda: athena.get_work_group(WorkGroup=busy_wg))
    assert code_busy_after == "InvalidRequestException", (
        f"expected busy workgroup to be gone after recursive delete, got {code_busy_after}"
    )
    assert msg_busy_after == "WorkGroup is not found.", msg_busy_after

    # Gone is also unusable: a mutation on the now-deleted workgroup fails the
    # same way an independent read does.
    code_mutation, msg_mutation = _error(lambda: athena.update_work_group(WorkGroup=busy_wg, Description="x"))
    assert code_mutation == "InvalidRequestException", (
        f"expected mutation on deleted workgroup to fail, got {code_mutation}"
    )
    assert msg_mutation == "WorkGroup is not found.", msg_mutation


def _create_bucket(ctx, s3, bucket: str, check_name: str) -> None:
    region = ctx.region
    # us-east-1 is S3's legacy default region and rejects an explicit
    # LocationConstraint for it; every other region requires one.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real-check", "Value": check_name},
    ]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _safe(fn) -> None:
    """Run a delete; only an unknown workgroup ("WorkGroup is not found.") counts as gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because accepting a call AWS refuses must not read as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result is not None:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
