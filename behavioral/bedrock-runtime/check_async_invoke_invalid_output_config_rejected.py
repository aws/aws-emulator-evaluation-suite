"""async-invoke-invalid-output-config-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "async-invoke-invalid-output-config-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

# The s3Uri legs test OUTPUT CONFIG validation, not modelInput, so any async-invocable model
# StartAsyncInvoke accepts shows the claim; an empty modelInput is accepted and only fails
# validation asynchronously, so no video is rendered.
_ASYNC_MODEL = "luma.ray-v2:0"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed S3 output URI is rejected with ValidationException before any job is created."""
    bedrock = ctx.client("bedrock-runtime")

    bad_config = {"s3OutputDataConfig": {"s3Uri": "not-a-valid-s3-uri"}}

    def _attempt():
        bedrock.start_async_invoke(
            modelId=_ASYNC_MODEL,
            modelInput={},
            outputDataConfig=bad_config,
        )

    code, message = _error(_attempt)
    assert code == "ValidationException", f"expected ValidationException for a malformed s3Uri, got {code!r}"
    assert message == "1 validation error detected: Value 'not-a-valid-s3-uri' at 'outputDataConfig.s3OutputDataConfig.s3Uri' failed to satisfy constraint: Member must satisfy regular expression pattern: s3://[a-z0-9][\\.\\-a-z0-9]{1,61}[a-z0-9](/.*)?", f"unexpected refusal message {message!r}"

    # effect absent: the malformed request raised before returning, so no invocationArn was ever
    # minted for it -- there is nothing to find via an independent read.
    # positive control: an identical request with a well-formed output config is ACCEPTED for
    # real (StartAsyncInvoke returns an invocationArn), and the started job is independently
    # readable through GetAsyncInvoke (a different operation than the one that started it), not
    # just the StartAsyncInvoke response itself.
    bucket = _create_output_bucket(ctx)
    arn = _start_async_job(ctx, bedrock, bucket)
    assert arn.startswith(f"arn:aws:bedrock:{ctx.region}:"), f"unexpected invocationArn shape: {arn!r}"

    control = bedrock.get_async_invoke(invocationArn=arn)
    assert control["invocationArn"] == arn, (
        f"GetAsyncInvoke returned a different invocationArn: {control['invocationArn']!r}"
    )
    assert control["status"] in ("InProgress", "Completed", "Failed"), (
        f"unexpected status for a freshly started job: {control['status']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError for a malformed s3Uri, but the call SUCCEEDED: {result!r}")


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs = {"Bucket": name}
    # us-east-1 is S3's default region and CreateBucket rejects an explicit LocationConstraint for it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _start_async_job(ctx, bedrock, bucket):
    resp = bedrock.start_async_invoke(
        modelId=_ASYNC_MODEL,
        modelInput={},
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}},
    )
    return resp["invocationArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
