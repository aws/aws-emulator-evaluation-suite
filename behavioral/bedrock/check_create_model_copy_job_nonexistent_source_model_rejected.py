"""create-model-copy-job-nonexistent-source-model-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-copy-job-nonexistent-source-model-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelCopyJob rejects a malformed sourceModelArn with ValidationException 'Provided ARN is
    invalid.' and a well-formed ARN naming a made-up base model with ValidationException naming that
    model as not a valid foundation model, and ListModelCopyJobs shows no job for the target name.
    """
    bedrock = ctx.client("bedrock")
    account_id = ctx.account

    # Must be >= the modeled minimum length of 20 for sourceModelArn so botocore's own
    # client-side length validation doesn't short-circuit the call before it reaches AWS;
    # it still doesn't match the required ARN pattern, so the server must reject it.
    malformed_arn = "not-an-arn-at-all-0123456789"
    malformed_code, malformed_message = _error_code_and_message(
        lambda: bedrock.create_model_copy_job(
            sourceModelArn=malformed_arn, targetModelName=ctx.unique_name("sim2real-copytarget-")
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected a malformed sourceModelArn to be rejected with ValidationException, got {malformed_code!r}"
    )
    assert malformed_message == "Provided ARN is invalid.", f"message={malformed_message!r}"

    # Syntactically well-formed (matches the documented ARN pattern) but the
    # embedded model name/hash is entirely made up.
    fake_base_model = "sim2real-noexist.v1"
    nonexistent_arn = f"arn:aws:bedrock:{ctx.region}:{account_id}:custom-model/{fake_base_model}/abcdef012345"
    target_name = ctx.unique_name("sim2real-copytarget-")
    notfound_code, notfound_message = _error_code_and_message(
        lambda: bedrock.create_model_copy_job(sourceModelArn=nonexistent_arn, targetModelName=target_name)
    )
    assert notfound_code == "ValidationException", (
        f"expected the same semantic ValidationException for a well-formed but nonexistent "
        f"sourceModelArn, got {notfound_code!r}"
    )
    expected_message = (
        f"The foundation model '{fake_base_model}' for custom model is not a valid foundation model"
    )
    assert notfound_message == expected_message, (
        f"expected message {expected_message!r}, got {notfound_message!r}"
    )

    # Effect absent: no copy job exists for our target name.
    listed = bedrock.list_model_copy_jobs().get("modelCopyJobSummaries", [])
    assert not any(j.get("targetModelName") == target_name for j in listed), (
        f"expected no model copy job to have been created for target={target_name!r}"
    )

    # Sanity control: the general capability (List) still works normally.
    bedrock.list_model_copy_jobs()


def _error_code_and_message(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
