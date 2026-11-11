"""async-invoke-schema-gap-rejected-only-after-accept."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-schema-gap-rejected-only-after-accept"
GROUP = 'async_invoke_rejected'
SERVICES = ['bedrock-runtime']

_ASYNC_MODEL = "luma.ray-v2:0"
_TERMINAL = ("Completed", "Failed")
_TERMINAL_TIMEOUT_S = 120.0
_WRITE_TIMEOUT_S = 60.0
_MANIFEST_RE = re.compile(r"^out/[a-z0-9]+/manifest\.json$")


def _error(fn):
    """Return (code, message) for a ClientError; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call was expected to be refused synchronously but returned success")


def _await_terminal(rt, arn):
    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    job = rt.get_async_invoke(invocationArn=arn)
    while job["status"] not in _TERMINAL:
        assert time.monotonic() < deadline, (
            f"async invoke {arn!r} never reached a terminal state within "
            f"{_TERMINAL_TIMEOUT_S}s; last status was {job['status']!r}"
        )
        time.sleep(3.0)
        job = rt.get_async_invoke(invocationArn=arn)
    return job


def _all_objects(s3, bucket):
    """Every object in *bucket*, following the continuation token to the end."""
    out, token = [], None
    while True:
        page = s3.list_objects_v2(
            Bucket=bucket, **({"ContinuationToken": token} if token else {})
        )
        out.extend(page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            return out


def _all_arns(rt, **kwargs):
    """Every invocation ARN matching *kwargs*, following the pagination token to the end.

    Other invocations in the account can push this one off page one."""
    arns, token = [], None
    while True:
        page = rt.list_async_invokes(**kwargs, **({"nextToken": token} if token else {}))
        arns.extend(s["invocationArn"] for s in page["asyncInvokeSummaries"])
        token = page.get("nextToken")
        if not token:
            return arns


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke rejects an undeclared modelInput key synchronously with ValidationException.

    A missing required key is accepted, then ends Failed ("prompt is required") with only a
    manifest written and no entry in the Completed partition."""
    rt = ctx.client("bedrock-runtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-brt-async-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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

    output = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}}

    # Positive control: the service DOES validate this payload synchronously when the schema can
    # decide. An undeclared key is refused before any job exists.
    code, message = _error(
        lambda: rt.start_async_invoke(
            modelId=_ASYNC_MODEL, modelInput={"sim2realBogusKey": 1}, outputDataConfig=output
        )
    )
    assert code == "ValidationException", (
        f"an undeclared modelInput key should be a synchronous ValidationException, got {code!r}"
    )
    assert message == (
        "Invalid JSON: : property 'sim2realBogusKey' is not defined in the schema and the "
        "schema does not allow additional properties "
    ), f"synchronous schema rejection carried an unexpected message: {message!r}"

    # Break exactly one thing: omit the required key instead of adding an undeclared one.
    started = rt.start_async_invoke(
        modelId=_ASYNC_MODEL, modelInput={}, outputDataConfig=output
    )
    arn = started["invocationArn"]
    assert arn, f"StartAsyncInvoke returned no invocationArn: {started!r}"

    job = _await_terminal(rt, arn)
    assert job["status"] == "Failed", (
        f"a modelInput missing the model's required key should end Failed, got {job['status']!r}"
    )
    assert job["failureMessage"] == "prompt is required", (
        f"expected failureMessage 'prompt is required', got {job.get('failureMessage')!r}"
    )
    assert "endTime" in job, (
        f"a terminal async invoke must carry endTime; GetAsyncInvoke returned keys {sorted(job)}"
    )

    # The effect is absent twice over: the job produced no rendered artefact -- only the request
    # manifest every invocation writes under its own id -- and it never enters the Completed
    # partition.
    invocation_id = arn.rpartition("/")[2]
    manifest_key = f"out/{invocation_id}/manifest.json"
    # The manifest write lags the status transition, so poll for it rather than assuming the two
    # are ordered. What is asserted is the FULL listing once it lands: the manifest and nothing
    # else, i.e. no rendered artefact was produced.
    deadline = time.monotonic() + _WRITE_TIMEOUT_S
    written = sorted(o["Key"] for o in _all_objects(s3, bucket))
    while manifest_key not in written:
        assert time.monotonic() < deadline, (
            f"{manifest_key!r} never appeared in {bucket!r} within {_WRITE_TIMEOUT_S}s of the job "
            f"reaching Failed; the bucket holds {written!r}"
        )
        time.sleep(3.0)
        written = sorted(o["Key"] for o in _all_objects(s3, bucket))
    # Two manifests, not one: the synchronously refused call also wrote a manifest, because the
    # manifest is written before the modelInput schema is checked.
    assert manifest_key in written, (
        f"the accepted job's manifest {manifest_key!r} is missing from {written!r}"
    )
    assert all(_MANIFEST_RE.match(k) for k in written), (
        f"a Failed async invoke must render nothing, but {bucket!r} holds a non-manifest key: "
        f"{[k for k in written if not _MANIFEST_RE.match(k)]!r}"
    )
    assert len(written) == 2, (
        f"expected exactly two manifests -- one for the refused control call, one for the accepted "
        f"job -- but {bucket!r} holds {written!r}"
    )
    manifest = json.loads(s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read())
    assert set(manifest) == {"requestId"}, (
        f"the manifest of a Failed invoke should carry only requestId, got {sorted(manifest)!r}"
    )
    assert str(uuid.UUID(manifest["requestId"])) == manifest["requestId"], (
        f"manifest requestId {manifest['requestId']!r} is not a canonical UUID"
    )

    completed = _all_arns(rt, statusEquals="Completed")
    assert arn not in completed, (
        f"{arn!r} failed but still appears in the Completed partition ({len(completed)} entries)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
