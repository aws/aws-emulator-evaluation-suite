"""sample-malformed-job-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sample-malformed-job-arn-rejected"
GROUP = "validation"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sample with a JobArn that fails the ARN pattern is refused with the malformed-ARN
    ValidationException (exact message), distinct from the "could not find job"
    ValidationException that a well-formed nonexistent JobArn gets.
    """
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    client = ctx.client("sagemakerjobruntime")
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    malformed_arn = "not-a-valid-job-arn"

    def _malformed_call():
        client.sample(
            JobArn=malformed_arn,
            TrajectoryId=trajectory_id,
            Body=body,
        )

    malformed = _error_code(_malformed_call)
    want = ("ValidationException", f"Input arn {malformed_arn} is malformed")
    assert malformed == want, f"expected the malformed-ARN rejection {want!r}, got {malformed!r}"

    well_formed_arn = _job_arn(ctx, account_id)

    def _control_call():
        client.sample(JobArn=well_formed_arn, TrajectoryId=trajectory_id, Body=body)

    control = _error_code(_control_call)
    want_control = ("ValidationException", f"Could not find job with jobArn {well_formed_arn}")
    assert control == want_control, (
        f"expected the well-formed (but nonexistent) JobArn to clear ARN-pattern validation "
        f"and reach the job-lookup layer with {want_control!r}, got {control!r} -- if this "
        f"also read as malformed, the target is not actually validating the ARN pattern"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _job_arn(ctx, account_id, job_name=None, job_type="AgentRFT"):
    name = job_name or ctx.unique_name("sim2real-sjr-job-")
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/{job_type}/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
