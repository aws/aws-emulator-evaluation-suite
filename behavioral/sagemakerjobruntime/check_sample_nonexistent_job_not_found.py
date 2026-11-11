"""sample-nonexistent-job-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sample-nonexistent-job-not-found"
GROUP = "not-found"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sample on a well-formed JobArn that was never created returns ValidationException with the
    exact "could not find job" message: this operation folds the job-existence check into request
    validation.
    """
    account_id = ctx.account
    job_arn = _job_arn(ctx, account_id)
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    client = ctx.client("sagemakerjobruntime")

    def _call():
        return client.sample(JobArn=job_arn, TrajectoryId=trajectory_id, Body=body)

    code, message = _error_code(_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Could not find job with jobArn {job_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _job_arn(ctx, account_id, job_name=None, job_type="AgentRFT"):
    name = job_name or ctx.unique_name("sim2real-sjr-job-")
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/{job_type}/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

