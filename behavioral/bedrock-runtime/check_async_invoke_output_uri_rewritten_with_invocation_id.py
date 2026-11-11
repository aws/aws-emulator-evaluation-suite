"""async-invoke-output-uri-rewritten-with-invocation-id."""
from __future__ import annotations

import re
import time
import urllib.parse
import uuid

from behavioral_harness import tags

CHECK = "async-invoke-output-uri-rewritten-with-invocation-id"
GROUP = 'async_invoke'
SERVICES = ['bedrock-runtime']

_ASYNC_MODEL = "luma.ray-v2:0"
_ARN_RE = re.compile(r"^arn:aws:bedrock:[a-z0-9-]{1,20}:[0-9]{12}:async-invoke/([a-z0-9]+)$")
_TERMINAL = ("Completed", "Failed")
_TERMINAL_TIMEOUT_S = 120.0


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAsyncInvoke reports the requested s3Uri prefix with the ARN's invocation id appended.

    It also reports a minted UUID clientRequestToken and an account-less foundation-model ARN."""
    rt = ctx.client("bedrock-runtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-brt-uri-")
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

    requested_prefix = "sim2real/renders/"
    started = rt.start_async_invoke(
        modelId=_ASYNC_MODEL,
        modelInput={},
        outputDataConfig={
            "s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/{requested_prefix}"}
        },
    )

    arn = started["invocationArn"]
    matched = _ARN_RE.match(arn)
    assert matched, f"invocationArn {arn!r} does not match the async-invoke ARN form"
    invocation_id = matched.group(1)

    job = rt.get_async_invoke(invocationArn=arn)
    assert job["invocationArn"] == arn, (
        f"GetAsyncInvoke echoed {job['invocationArn']!r}, not the ARN StartAsyncInvoke minted ({arn!r})"
    )

    reported = job["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"]
    parsed = urllib.parse.urlparse(reported)
    assert parsed.scheme == "s3", f"reported output URI {reported!r} is not an s3:// URI"
    assert parsed.netloc == bucket, (
        f"reported output URI names bucket {parsed.netloc!r}, not the one requested ({bucket!r})"
    )
    assert parsed.path.lstrip("/") == requested_prefix + invocation_id, (
        f"expected the requested prefix with the invocation id appended "
        f"({requested_prefix + invocation_id!r}), got {parsed.path.lstrip('/')!r}"
    )

    # An idempotency token the caller never sent is minted for it, as a UUID.
    minted_token = job.get("clientRequestToken")
    assert minted_token, (
        f"StartAsyncInvoke supplied no clientRequestToken, so the service must mint one; "
        f"GetAsyncInvoke reported {minted_token!r}"
    )
    assert str(uuid.UUID(minted_token)) == minted_token, (
        f"minted clientRequestToken {minted_token!r} is not a canonical UUID"
    )

    # The foundation-model ARN the job records carries an EMPTY account field: the model is
    # AWS-owned, not account-owned.
    assert job["modelArn"] == f"arn:aws:bedrock:{ctx.region}::foundation-model/{_ASYNC_MODEL}", (
        f"job recorded modelArn {job['modelArn']!r} for a request naming {_ASYNC_MODEL!r}"
    )

    # Let the job settle so cleanup does not race a writer into the bucket it is emptying.
    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    while job["status"] not in _TERMINAL:
        assert time.monotonic() < deadline, (
            f"async invoke {arn!r} never reached a terminal state within {_TERMINAL_TIMEOUT_S}s; "
            f"last status was {job['status']!r}"
        )
        time.sleep(3.0)
        job = rt.get_async_invoke(invocationArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
