"""start-async-invoke-unsupported-model-wrong-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-async-invoke-unsupported-model-wrong-state-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]

# The video-output model ListFoundationModels offers in us-west-2; Nova Reel is not offered there.
_ASYNC_CAPABLE_MODEL_ID = "luma.ray-v2:0"

# A live on-demand text model: a retired one (e.g. titan-text-express-v1) answers
# ResourceNotFoundException "end of its life" for every operation, not the async refusal.
_TEXT_ONLY_MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke on an on-demand text model is rejected with ValidationException naming the
    async-inference incompatibility and creates no job; an async-capable model is accepted."""
    client = ctx.client("bedrock-runtime")
    bucket = _create_output_bucket(ctx)

    code, message = _error_code(
        lambda: client.start_async_invoke(
            modelId=_TEXT_ONLY_MODEL_ID,
            modelInput={
                "schemaVersion": "messages-v1",
                "messages": [{"role": "user", "content": [{"text": "hello"}]}],
                "inferenceConfig": {"maxTokens": 10},
            },
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/unsupported/"}},
        )
    )
    assert code == "ValidationException", f"got code={code!r} message={message!r}"
    assert message == "The provided model doesn't support async inference.", (
        f"the refusal must name the async-inference incompatibility, distinguishing it from a "
        f"generic validation failure or a not-found; got message={message!r}"
    )

    listed = client.list_async_invokes(maxResults=50)
    for summary in listed.get("asyncInvokeSummaries", []):
        s3_cfg = summary.get("outputDataConfig", {}).get("s3OutputDataConfig", {})
        assert "unsupported/" not in s3_cfg.get("s3Uri", ""), (
            f"a rejected StartAsyncInvoke must leave no trace in list_async_invokes; "
            f"found {s3_cfg.get('s3Uri', '')!r}"
        )

    start = client.start_async_invoke(
        modelId=_ASYNC_CAPABLE_MODEL_ID,
        modelInput={"prompt": "A calm lake at sunrise, cinematic."},
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/supported/"}},
    )
    assert start["invocationArn"].startswith("arn:aws"), (
        f"a successful StartAsyncInvoke must return a real ARN; got {start['invocationArn']!r}"
    )
    status = client.get_async_invoke(invocationArn=start["invocationArn"])["status"]
    assert status in ("InProgress", "Completed"), (
        f"the async-capable model's job must be accepted and progressing; got status={status!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"the call was expected to be refused but SUCCEEDED, which is an over-permissiveness "
        f"finding, not a code mismatch; response={resp!r}"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-").replace("_", "-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    for _ in range(3):
        objects = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if not objects:
            break
        s3.delete_objects(
            Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}
        )
        time.sleep(1)
    s3.delete_bucket(Bucket=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
