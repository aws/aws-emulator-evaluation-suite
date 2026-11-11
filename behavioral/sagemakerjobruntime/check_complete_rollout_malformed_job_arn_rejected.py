"""complete-rollout-malformed-job-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-rollout-malformed-job-arn-rejected"
GROUP = "validation"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteRollout with a JobArn that fails the ARN pattern is refused with ValidationException
    and its exact message, while a well-formed but nonexistent JobArn gets
    ResourceNotFoundException (exact message).
    """
    client = ctx.client("sagemakerjobruntime")
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    malformed_arn = ":definitely/not-an-arn:: 123"

    code, message = _error_code(lambda: client.complete_rollout(
        JobArn=malformed_arn,
        TrajectoryId=trajectory_id,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Input arn {malformed_arn} is malformed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a well-formed-but-nonexistent JobArn passes ARN
    # syntax validation and instead fails on job existence -- a distinct
    # error class -- so the rejection above is not just "CompleteRollout
    # rejects everything".
    account_id = ctx.account
    well_formed_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/AgentRFT/"
        + ctx.unique_name("sim2real-sjr-job-")
    )
    control_code, control_message = _error_code(lambda: client.complete_rollout(
        JobArn=well_formed_arn,
        TrajectoryId=trajectory_id,
    ))
    assert control_code == "ResourceNotFoundException", (
        f"expected a well-formed-but-nonexistent JobArn to fail on job "
        f"existence with ResourceNotFoundException, got {control_code}"
    )
    expected_control = f"Trajectory {trajectory_id} not found for account {account_id}"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )
    assert control_code != code, (
        "the malformed-ARN and nonexistent-job rejections must be "
        "distinguishable error classes"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
