"""sample-with-response-stream-nonexistent-job-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sample-with-response-stream-nonexistent-job-not-found"
GROUP = "not-found"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SampleWithResponseStream against a well-formed but never-created
    JobArn returns ValidationException ("could not find job") on the initial
    call, without ever handing back a stream to iterate."""
    account_id = ctx.account
    job_arn = _job_arn(ctx, account_id)
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    client = ctx.client("sagemakerjobruntime")
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

    assert response is None, "nonexistent job must not yield a stream response object"
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Could not find job with jobArn {job_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _job_arn(ctx, account_id, job_name=None, job_type="AgentRFT"):
    name = job_name or ctx.unique_name("sim2real-sjr-job-")
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/{job_type}/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
