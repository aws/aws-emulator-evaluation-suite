"""bedrock-runtime-async-invoke-with-a-nonexistent-output-bucket-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-async-invoke-with-a-nonexistent-output-bucket-rejected"
GROUP = 'overly-permissive'
SERVICES = ['bedrock-runtime', 's3']

# A model whose outputModalities include VIDEO, as StartAsyncInvoke requires.
ASYNC_MODEL = "luma.ray-v2:0"

_MODEL_INPUT = {
    "prompt": "A single blue cube rotating slowly on a white background.",
    "aspect_ratio": "16:9",
    "loop": False,
    "duration": "5s",
    "resolution": "540p",
}
#: There is NO CancelAsyncInvoke in the bedrock-runtime Smithy model, so the accepted control
#: invocation must be polled to a terminal status before cleanup removes the bucket underneath it.
_TERMINAL_TIMEOUT_S = 240
_POLL_INTERVAL_S = 2.0


def _start_with_backoff(fn):
    """Start the accepted control invocation, retrying ONLY a throttle.

    Accounts admit very few concurrent async invocations; the refused leg is never retried.
    """
    deadline = time.monotonic() + 180
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _error_code_only(fn):
    """The AWS error code a call raised, or 'NO-ERROR'. Never a falsy sentinel."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")
    return "NO-ERROR"


def _error_code(fn):
    """Return (code, message), or RAISE if the call unexpectedly succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code", ""),
                exc.response.get("Error", {}).get("Message", ""))
    raise AssertionError(
        f"StartAsyncInvoke was ACCEPTED against a bucket that does not exist. That is an "
        f"over-permissiveness finding, not a code mismatch: the destination is validated up front "
        f"precisely so a caller is not billed for an undeliverable artifact. response={resp!r}"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke refuses an absent output bucket at submit time with ValidationException and
    creates no invocation, while the identical request against an existing bucket completes.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_StartAsyncInvoke.html
    """
    rt = ctx.client("bedrock-runtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-async-out-")
    s3.create_bucket(Bucket=bucket,
                     CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _drop_bucket():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_drop_bucket)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [
                              {"Key": "sim2real", "Value": "async-invoke"},
                              {"Key": "sim2real:managed", "Value": "true"}]})

    # A bucket name that is syntactically valid and does not exist. Derived from this run's unique
    # name so no concurrently running suite can create it underneath the assertion.
    missing_bucket = ctx.unique_name("sim2real-absent-dest-")
    missing_uri = f"s3://{missing_bucket}/video/"
    # Guard the premise rather than assuming it: if this name somehow resolves, the refusal below
    # would be testing something else entirely. GetBucketLocation is used rather than HeadBucket
    # because HeadBucket has no response body and botocore therefore surfaces the bare HTTP status
    # '404' as the error code, which is not an AWS error code at all.
    assert _error_code_only(lambda: s3.get_bucket_location(Bucket=missing_bucket)) \
        == "NoSuchBucket", (
        f"the bucket chosen as the absent destination {missing_bucket!r} must really be absent "
        f"before the refusal is attributed to its absence; GetBucketLocation returned "
        f"{_error_code_only(lambda: s3.get_bucket_location(Bucket=missing_bucket))!r}"
    )

    # Barrier: the identical request against a bucket that DOES exist is accepted, and is polled
    # all the way to a terminal status BEFORE the refusal is attempted. Both halves matter.
    # Terminal-first matters: with the accepted job still InProgress, the refused call is throttled
    # for capacity before its destination is validated. There is also no Cancel operation.
    accepted = _start_with_backoff(lambda: rt.start_async_invoke(
        modelId=ASYNC_MODEL,
        modelInput=_MODEL_INPUT,
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/video/"}},
        tags=[{"key": "sim2real", "value": "async-invoke"},
              {"key": "sim2real:managed", "value": "true"}],
    ))
    arn = accepted["invocationArn"]
    assert arn.startswith("arn:aws:bedrock:"), (
        f"the accepted control must return a bedrock async-invoke ARN; got {arn!r}"
    )

    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    job = rt.get_async_invoke(invocationArn=arn)
    while job["status"] == "InProgress":
        assert time.monotonic() < deadline, (
            f"the control invocation was still InProgress after {_TERMINAL_TIMEOUT_S}s and cannot "
            f"be cancelled; arn={arn!r} job={job!r}"
        )
        time.sleep(_POLL_INTERVAL_S)
        job = rt.get_async_invoke(invocationArn=arn)
    assert job["status"] == "Completed", (
        f"the accepted control must complete, else the refusal below cannot be attributed to the "
        f"destination; status={job['status']!r} failureMessage={job.get('failureMessage')!r}"
    )

    # Break exactly ONE thing: the same request naming the absent bucket.
    code, message = _error_code(
        lambda: rt.start_async_invoke(
            modelId=ASYNC_MODEL,
            modelInput=_MODEL_INPUT,
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": missing_uri}},
        )
    )
    assert code == "ValidationException", (
        f"StartAsyncInvoke naming a bucket that does not exist must be refused with "
        f"ValidationException; got {code!r} message={message!r}"
    )
    assert message == "Invalid S3 credentials", (
        f"a missing output bucket is refused with the same message as unwritable S3 credentials "
        f"-- there is no dedicated 'bucket not found' message; got {message!r}"
    )

    # Effect absent: no invocation in this account points at the bucket that does not exist.
    # Paginated: other invocations in the account can fill page one.
    destinations = {}
    for page in rt.get_paginator("list_async_invokes").paginate():
        for summary in page["asyncInvokeSummaries"]:
            destinations[summary["invocationArn"]] = (
                summary.get("outputDataConfig", {})
                .get("s3OutputDataConfig", {}).get("s3Uri", ""))
    orphans = {a: uri for a, uri in destinations.items() if missing_bucket in uri}
    assert not orphans, (
        f"the refused submission must not have created an invocation at all, yet "
        f"ListAsyncInvokes reports work aimed at the absent bucket: {orphans!r}"
    )
    assert destinations.get(arn, "").startswith(f"s3://{bucket}/video/"), (
        f"the accepted control must be listed against the bucket it was given, which is what "
        f"proves the absence above is a real absence and not an empty listing; got "
        f"{destinations.get(arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
