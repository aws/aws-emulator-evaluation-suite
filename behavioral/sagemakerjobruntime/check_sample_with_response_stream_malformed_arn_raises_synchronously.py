"""sample-with-response-stream-malformed-arn-raises-synchronously."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sample-with-response-stream-malformed-arn-raises-synchronously"
GROUP = "validation"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SampleWithResponseStream with a malformed JobArn raises ValidationException (exact
    message) on the call itself with no stream returned, while a well-formed nonexistent
    JobArn raises a different ValidationException.
    """
    client = ctx.client("sagemakerjobruntime")
    account_id = ctx.account
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    def _call(job_arn):
        response = None
        code = None
        message = None
        try:
            response = client.sample_with_response_stream(
                JobArn=job_arn, TrajectoryId=trajectory_id, Body=body
            )
        except ClientError as exc:
            err = exc.response["Error"]
            code = err["Code"]
            message = err.get("Message")
        return response, code, message

    malformed_arn = "not-a-valid-job-arn"
    response, code, message = _call(malformed_arn)
    assert response is None, "malformed ARN must not yield a stream response object"
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Input arn {malformed_arn} is malformed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    well_formed_job_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/AgentRFT/"
        + ctx.unique_name("sim2real-sjr-job-")
    )
    control_response, control_code, control_message = _call(well_formed_job_arn)
    assert control_response is None, (
        "well-formed but nonexistent job must not yield a stream response object either"
    )
    assert control_code == "ValidationException", (
        "expected the well-formed-but-nonexistent control to also be a "
        f"ValidationException, got {control_code}"
    )
    expected_control = f"Could not find job with jobArn {well_formed_job_arn}"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )
    assert (message or "") != (control_message or ""), (
        "the malformed-ARN rejection and the well-formed-but-nonexistent rejection must "
        "carry distinct messages -- proving the ARN-format check is a distinct stage from "
        f"the job lookup -- but both were {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
