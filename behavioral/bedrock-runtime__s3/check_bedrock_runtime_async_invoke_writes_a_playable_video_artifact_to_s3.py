"""bedrock-runtime-async-invoke-writes-a-playable-video-artifact-to-s3."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-async-invoke-writes-a-playable-video-artifact-to-s3"
GROUP = 'async-invoke'
SERVICES = ['bedrock-runtime', 's3']

# A foundation model whose outputModalities include VIDEO.
ASYNC_MODEL = "luma.ray-v2:0"

#: The smallest / cheapest job this model accepts; it completes in about 70 s.
_MODEL_INPUT = {
    "prompt": "A single blue cube rotating slowly on a white background.",
    "aspect_ratio": "16:9",
    "loop": False,
    "duration": "5s",
    "resolution": "540p",
}
#: Bounded inside the 300 s per-check ceiling. There is NO CancelAsyncInvoke / StopAsyncInvoke operation in the bedrock-runtime Smithy model,
#: so an abandoned invocation cannot be recalled: the poll below must reach a terminal status
#: before cleanup empties the bucket, or the service writes into a bucket that is being deleted.
_TERMINAL_TIMEOUT_S = 240
_POLL_INTERVAL_S = 2.0
_ISO_BMFF_BOX = b"ftyp"


def _start_with_backoff(fn):
    """Start the invocation, retrying ONLY a throttle.

    Accounts admit very few concurrent async invocations, so concurrent async jobs throttle each
    other.
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke writes a real MP4 (ftyp box) and manifest under the caller's prefix plus the
    service-minted invocation id, and ListAsyncInvokes agrees with GetAsyncInvoke on the outcome.

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

    # Registered immediately after the create it undoes, and BEFORE the invocation is started, so
    # that a failure anywhere below still tears the bucket down.
    ctx.on_cleanup(_drop_bucket)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [
                              {"Key": "sim2real", "Value": "async-invoke"},
                              {"Key": "sim2real:managed", "Value": "true"}]})

    prefix = "video/"
    requested_uri = f"s3://{bucket}/{prefix}"
    started = _start_with_backoff(lambda: rt.start_async_invoke(
        modelId=ASYNC_MODEL,
        modelInput=_MODEL_INPUT,
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": requested_uri}},
        tags=[{"key": "sim2real", "value": "async-invoke"},
              {"key": "sim2real:managed", "value": "true"}],
    ))
    arn = started["invocationArn"]
    assert arn.startswith("arn:aws:bedrock:"), (
        f"StartAsyncInvoke must return a bedrock async-invoke ARN; got {arn!r}"
    )
    invocation_id = arn.rsplit("/", 1)[-1]
    assert invocation_id, f"the returned ARN carries no invocation id; got {arn!r}"

    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    job = rt.get_async_invoke(invocationArn=arn)
    while job["status"] == "InProgress":
        assert time.monotonic() < deadline, (
            f"the invocation was still InProgress after {_TERMINAL_TIMEOUT_S}s; the bucket is "
            f"about to be torn down under a job that cannot be cancelled. arn={arn!r} job={job!r}"
        )
        time.sleep(_POLL_INTERVAL_S)
        job = rt.get_async_invoke(invocationArn=arn)

    assert job["status"] == "Completed", (
        f"the asynchronous invocation did not complete; status={job['status']!r} "
        f"failureMessage={job.get('failureMessage')!r}"
    )
    assert job["invocationArn"] == arn, (
        f"GetAsyncInvoke must echo the ARN it was asked about; got {job['invocationArn']!r}"
    )
    assert job["modelArn"].endswith(f"foundation-model/{ASYNC_MODEL}"), (
        f"the job record must name the foundation model that ran; got {job['modelArn']!r}"
    )
    assert job["endTime"] >= job["submitTime"], (
        f"a completed job's endTime cannot precede its submitTime; submitTime="
        f"{job['submitTime']!r} endTime={job['endTime']!r}"
    )

    # The output location is DERIVED from the invocation the service minted, not echoed back.
    written_uri = job["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"]
    assert written_uri == f"{requested_uri}{invocation_id}", (
        f"the recorded output URI must be the requested prefix with the service-minted invocation "
        f"id appended; requested {requested_uri!r} invocation {invocation_id!r} recorded "
        f"{written_uri!r}"
    )

    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=f"{prefix}{invocation_id}/"):
        keys += [o["Key"] for o in page.get("Contents", [])]
    mp4_keys = [k for k in keys if k.endswith(".mp4")]
    assert len(mp4_keys) == 1, (
        f"exactly one .mp4 artifact expected under the invocation's own prefix; keys under "
        f"{prefix}{invocation_id}/ were {sorted(keys)!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=mp4_keys[0])
    assert head["ContentLength"] > 10240, (
        f"the artifact is present but implausibly small for five seconds of video: "
        f"{head['ContentLength']} bytes at {mp4_keys[0]!r}"
    )
    first16 = s3.get_object(Bucket=bucket, Key=mp4_keys[0],
                            Range="bytes=0-15")["Body"].read()
    assert first16[4:8] == _ISO_BMFF_BOX, (
        f"the artifact must be an ISO base media file format container -- bytes 4..8 of an MP4 are "
        f"the 'ftyp' box type, and any non-empty blob would satisfy a size check alone; got "
        f"{first16!r}"
    )

    # The manifest the service writes alongside the video ties the object back to the request that
    # produced it, which is what distinguishes a real artifact from a file dropped in the prefix.
    manifest_keys = [k for k in keys if k.endswith("manifest.json")]
    assert len(manifest_keys) == 1, (
        f"exactly one manifest.json expected beside the video; keys were {sorted(keys)!r}"
    )
    manifest = json.loads(
        s3.get_object(Bucket=bucket, Key=manifest_keys[0])["Body"].read())
    assert manifest.get("requestId"), (
        f"the manifest must carry the requestId of the invocation that wrote it; got {manifest!r}"
    )

    # Two independent reads of the same server-side state must agree. Paginated because other
    # invocations in the account can push this one off page one.
    listed = {}
    for page in rt.get_paginator("list_async_invokes").paginate():
        for summary in page["asyncInvokeSummaries"]:
            listed[summary["invocationArn"]] = summary
    assert arn in listed, (
        f"ListAsyncInvokes must include the invocation GetAsyncInvoke just described; it listed "
        f"{sorted(listed)!r}"
    )
    assert listed[arn]["status"] == job["status"], (
        f"ListAsyncInvokes and GetAsyncInvoke must agree on the terminal status; list said "
        f"{listed[arn]['status']!r} get said {job['status']!r}"
    )
    assert (listed[arn]["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"]
            == written_uri), (
        f"the summary must carry the same output URI as the detailed record; list said "
        f"{listed[arn]['outputDataConfig']!r} get said {written_uri!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
