"""start-async-invoke-token-reuse-conflicting-params-blocked."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "start-async-invoke-token-reuse-conflicting-params-blocked"
GROUP = "concurrency"
SERVICES = ["bedrock-runtime"]

_ARN_RE = re.compile(r"^arn:aws:bedrock:[a-z0-9-]{1,20}:[0-9]{12}:async-invoke/([a-z0-9]+)$")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing the same clientRequestToken with different StartAsyncInvoke parameters
    is rejected with ConflictException; the original job is left untouched and no
    second job is created."""
    # Nova Reel is not invocable in every commercial region (elsewhere StartAsyncInvoke raises
    # ValidationException("The provided model identifier is invalid")); us-east-1 is where it resolves, so both the model and its output bucket are
    # pinned there rather than following ctx.region.
    client = ctx.client("bedrock-runtime", region="us-east-1")
    bucket = _create_output_bucket(ctx)
    token = ctx.unique_name("sim2real-conflict-")

    original_prefix = f"s3://{bucket}/original/"
    first = client.start_async_invoke(
        clientRequestToken=token,
        modelId="amazon.nova-reel-v1:1",
        modelInput={
            "taskType": "TEXT_VIDEO",
            "textToVideoParams": {"text": "A red bicycle leaning against a brick wall."},
            "videoGenerationConfig": {
                "durationSeconds": 6,
                "fps": 24,
                "dimension": "1280x720",
                "seed": 21,
            },
        },
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": original_prefix}},
    )
    first_arn = first["invocationArn"]
    first_arn_match = _ARN_RE.match(first_arn)
    assert first_arn_match, f"invocationArn {first_arn!r} does not match the async-invoke ARN form"
    # The service does not echo the caller's prefix verbatim -- it strips the trailing delimiter and
    # appends the invocation id it minted into the ARN. The prefix already ends in "/", so the
    # rewritten URI is the prefix with the id appended directly.
    first_expected_uri = original_prefix + first_arn_match.group(1)

    conflicting_prefix = f"s3://{bucket}/conflicting/"
    code, message = _error_code(
        lambda: client.start_async_invoke(
            clientRequestToken=token,
            modelId="amazon.nova-reel-v1:1",
            modelInput={
                "taskType": "TEXT_VIDEO",
                # Different prompt -> conflicting parameters under the same token.
                "textToVideoParams": {"text": "A completely different scene: a busy city street."},
                "videoGenerationConfig": {
                    "durationSeconds": 6,
                    "fps": 24,
                    "dimension": "1280x720",
                    "seed": 21,
                },
            },
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": conflicting_prefix}},
        )
    )
    assert code == "ConflictException", f"got {code!r}"
    assert message == (
        "Received a request with a client request token that has been used for a different input."
    ), message

    # Effect absent: the original job is unaffected -- still resolvable, still pointed
    # at the ORIGINAL output prefix, not silently overwritten by the conflicting call.
    original_after = client.get_async_invoke(invocationArn=first_arn)
    assert original_after["invocationArn"] == first_arn, (
        f"the original job's ARN changed across the rejected conflicting call: "
        f"expected {first_arn!r}, got {original_after['invocationArn']!r}"
    )
    assert (
        original_after["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"] == first_expected_uri
    ), (
        f"the original job's output location was overwritten by the rejected conflicting call: "
        f"expected {first_expected_uri!r} (the original prefix with its own invocation id "
        f"appended), got "
        f"{original_after['outputDataConfig']['s3OutputDataConfig']['s3Uri']!r}"
    )
    assert original_after["status"] in ("InProgress", "Completed"), (
        f"expected the untouched original job to be InProgress or Completed, "
        f"got {original_after['status']!r}"
    )

    # Positive control: a brand-new distinct token succeeds and creates a genuinely
    # new, different job.
    new_token = ctx.unique_name("sim2real-conflict-control-")
    control = client.start_async_invoke(
        clientRequestToken=new_token,
        modelId="amazon.nova-reel-v1:1",
        modelInput={
            "taskType": "TEXT_VIDEO",
            "textToVideoParams": {"text": "A single lighthouse on a rocky coast."},
            "videoGenerationConfig": {
                "durationSeconds": 6,
                "fps": 24,
                "dimension": "1280x720",
                "seed": 31,
            },
        },
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/control/"}},
    )
    assert control["invocationArn"] != first_arn, (
        f"a distinct clientRequestToken must mint a distinct job, but the control reused "
        f"{first_arn!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3", region="us-east-1")
    name = ctx.unique_name("sim2real-bedrock-async-").replace("_", "-").lower()
    s3.create_bucket(Bucket=name)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3", region="us-east-1")
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
