"""start-async-invoke-rejects-destination-before-model-input."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-async-invoke-rejects-destination-before-model-input"
GROUP = 'async_invoke_rejected'
SERVICES = ['bedrock-runtime']

_ASYNC_MODEL = "luma.ray-v2:0"
_BAD_INPUT = {"sim2realBogusKey": 1}
_SCHEMA_MESSAGE = (
    "Invalid JSON: : property 'sim2realBogusKey' is not defined in the schema and the schema "
    "does not allow additional properties "
)


_MANIFEST_RE = re.compile(r"^out/[a-z0-9]+/manifest\.json$")


def _error(fn):
    """Return (code, message) for a ClientError; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call was expected to be refused but returned success")


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


def _summaries(rt):
    """Every async-invoke summary in the account, following the pagination token to the end."""
    out, token = [], None
    while True:
        page = rt.list_async_invokes(**({"nextToken": token} if token else {}))
        out.extend(page["asyncInvokeSummaries"])
        token = page.get("nextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unwritable destination is refused before a schema-invalid modelInput is checked.
    The same bad input yields the schema error with a writable bucket and the S3 error without."""
    rt = ctx.client("bedrock-runtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-async-out-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

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

    absent_bucket = ctx.unique_name("sim2real-behav-brt-absent-")

    # Positive control: with a writable destination, the model's own schema DOES reject the input.
    writable_code, writable_message = _error(
        lambda: rt.start_async_invoke(
            modelId=_ASYNC_MODEL,
            modelInput=_BAD_INPUT,
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}},
        )
    )
    assert writable_code == "ValidationException", (
        f"an undeclared modelInput key should be a ValidationException, got {writable_code!r}"
    )
    assert writable_message == _SCHEMA_MESSAGE, (
        f"positive control: expected the model's schema complaint, got {writable_message!r}"
    )

    # Break exactly one thing: the destination bucket does not exist. The modelInput is unchanged
    # and still schema-invalid.
    absent_code, absent_message = _error(
        lambda: rt.start_async_invoke(
            modelId=_ASYNC_MODEL,
            modelInput=_BAD_INPUT,
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{absent_bucket}/out/"}},
        )
    )
    assert absent_code == "ValidationException", (
        f"an unwritable destination should be a ValidationException, got {absent_code!r}"
    )
    assert absent_message == "Invalid S3 credentials", (
        f"expected the destination complaint to pre-empt the schema complaint, got "
        f"{absent_message!r}"
    )
    assert absent_message != writable_message, (
        f"both requests reported {writable_message!r}, so the destination fault is invisible"
    )

    # The effect is absent where it counts: neither refused request minted a JOB against either
    # destination, so neither is visible to GetAsyncInvoke or ListAsyncInvokes.
    destinations = {
        s["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"] for s in _summaries(rt)
    }
    leaked = {u for u in destinations if bucket in u or absent_bucket in u}
    assert not leaked, (
        f"a refused StartAsyncInvoke must mint no job, but ListAsyncInvokes reports "
        f"{sorted(leaked)!r}"
    )

    # The schema-refused request has already written an invocation manifest; the request
    # stopped at the destination wrote nothing.
    written = sorted(o["Key"] for o in _all_objects(s3, bucket))
    assert len(written) == 1 and _MANIFEST_RE.match(written[0]), (
        f"the schema-refused request should have left exactly one invocation manifest in "
        f"{bucket!r}; found {written!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
