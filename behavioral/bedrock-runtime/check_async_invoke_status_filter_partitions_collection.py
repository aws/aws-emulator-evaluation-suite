"""async-invoke-status-filter-partitions-collection."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "async-invoke-status-filter-partitions-collection"
GROUP = 'async_invoke'
SERVICES = ['bedrock-runtime']

_ASYNC_MODEL = "luma.ray-v2:0"
_STATUSES = ("Completed", "InProgress", "Failed")
_TERMINAL_TIMEOUT_S = 120.0


def _all_arns(rt, **kwargs):
    """Every invocation ARN matching *kwargs*, following the pagination token to the end.

    Other invocations in the account can push this one off page one, even under `statusEquals`."""
    arns, token = [], None
    while True:
        page = rt.list_async_invokes(**kwargs, **({"nextToken": token} if token else {}))
        arns.extend(s["invocationArn"] for s in page["asyncInvokeSummaries"])
        token = page.get("nextToken")
        if not token:
            return arns


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListAsyncInvokes statusEquals partitions jobs: a Failed job is listed only under Failed.

    It is also listed unfiltered, and excluded by a submitTimeBefore window ending before it."""
    rt = ctx.client("bedrock-runtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-brt-list-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    def _drop_bucket():
        token = None
        while True:
            page = s3.list_objects_v2(
                Bucket=bucket, **({"ContinuationToken": token} if token else {})
            )
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            token = page.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_drop_bucket)

    arn = rt.start_async_invoke(
        modelId=_ASYNC_MODEL,
        modelInput={},
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}},
        tags=[{"key": "simparity-check", "value": CHECK}],
    )["invocationArn"]

    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    status = rt.get_async_invoke(invocationArn=arn)["status"]
    while status == "InProgress":
        assert time.monotonic() < deadline, (
            f"async invoke {arn!r} was still InProgress after {_TERMINAL_TIMEOUT_S}s"
        )
        time.sleep(3.0)
        status = rt.get_async_invoke(invocationArn=arn)["status"]
    assert status == "Failed", (
        f"an empty modelInput should end Failed, not {status!r}; the partition assertions below "
        f"are written against Failed"
    )
    job = rt.get_async_invoke(invocationArn=arn)
    assert job["failureMessage"] == "prompt is required", (
        f"expected failureMessage 'prompt is required' for an empty modelInput against "
        f"{_ASYNC_MODEL!r}, got {job.get('failureMessage')!r}"
    )

    by_status = {s: _all_arns(rt, statusEquals=s) for s in _STATUSES}
    assert arn in by_status["Failed"], (
        f"{arn!r} is Failed but statusEquals=Failed returned {len(by_status['Failed'])} entries "
        f"without it"
    )
    assert arn not in by_status["InProgress"], (
        f"{arn!r} reached Failed but statusEquals=InProgress still lists it"
    )
    assert arn not in by_status["Completed"], (
        f"{arn!r} is Failed but statusEquals=Completed lists it"
    )

    unfiltered = _all_arns(rt)
    assert arn in unfiltered, (
        f"{arn!r} is missing from the unfiltered collection ({len(unfiltered)} entries)"
    )

    # A window that closes before the job was submitted must exclude it, and the exclusion is not
    # the empty answer -- the same window with no upper bound still holds it.
    submitted = rt.get_async_invoke(invocationArn=arn)["submitTime"]
    before = _all_arns(rt, submitTimeBefore=submitted - datetime.timedelta(seconds=60))
    assert arn not in before, (
        f"{arn!r} was submitted at {submitted.isoformat()} but appears in a window ending 60s earlier"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
