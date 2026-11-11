"""update-reward-malformed-job-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-reward-malformed-job-arn-rejected"
GROUP = "validation"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateReward with a JobArn that fails the ARN pattern is refused with ValidationException
    (exact message), while a well-formed never-created JobArn with the same body gets
    ResourceNotFoundException (exact message).
    """
    account_id = ctx.account
    client = ctx.client("sagemakerjobruntime")
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    well_formed_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/AgentRFT/"
        f"{ctx.unique_name('sim2real-sjr-job-')}"
    )

    def _control():
        client.update_reward(JobArn=well_formed_arn, TrajectoryId=trajectory_id, Rewards=[1.0])

    control_code, control_message = _error_code(_control)
    assert control_code == "ResourceNotFoundException", (
        f"positive control: a well-formed but nonexistent JobArn should pass ARN "
        f"validation and fail with ResourceNotFoundException, got {control_code}"
    )
    expected_control = f"Trajectory {trajectory_id} not found for account {account_id}"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )
    malformed_arn = "totally-bogus-arn"

    def _call():
        client.update_reward(
            JobArn=malformed_arn,
            TrajectoryId=trajectory_id,
            Rewards=[1.0],
        )

    code, message = _error_code(_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Input arn {malformed_arn} is malformed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
