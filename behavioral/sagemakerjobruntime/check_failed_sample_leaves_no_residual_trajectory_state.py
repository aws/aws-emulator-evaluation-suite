"""failed-sample-leaves-no-residual-trajectory-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-sample-leaves-no-residual-trajectory-state"
GROUP = "state"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sample on a job never created fails with ValidationException (exact message) and leaves no
    trajectory state: CompleteRollout and UpdateReward on the same JobArn and TrajectoryId then
    return ResourceNotFoundException with the exact message, never a conflict or a success.
    """
    account_id = ctx.account
    job_arn = _job_arn(ctx, account_id)
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    client = ctx.client("sagemakerjobruntime")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    def _sample_call():
        client.sample(JobArn=job_arn, TrajectoryId=trajectory_id, Body=body)

    sample_code, sample_message = _error_code(_sample_call)
    assert sample_code == "ValidationException", (
        f"expected the initial Sample call to fail ValidationException "
        f"('could not find job'), got {sample_code}"
    )
    expected_sample = f"Could not find job with jobArn {job_arn}"
    assert sample_message == expected_sample, (
        f"expected message {expected_sample!r}, got {sample_message!r}"
    )
    expected_not_found = f"Trajectory {trajectory_id} not found for account {account_id}"

    def _complete_call():
        client.complete_rollout(JobArn=job_arn, TrajectoryId=trajectory_id)

    complete_code, complete_message = _error_code(_complete_call)
    assert complete_code == "ResourceNotFoundException", (
        f"expected CompleteRollout on the same trajectory to fail "
        f"ResourceNotFoundException (no residual state from the failed Sample), got {complete_code}"
    )
    assert complete_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {complete_message!r}"
    )

    def _reward_call():
        client.update_reward(JobArn=job_arn, TrajectoryId=trajectory_id, Rewards=[1.0])

    reward_code, reward_message = _error_code(_reward_call)
    assert reward_code == "ResourceNotFoundException", (
        f"expected UpdateReward on the same trajectory to fail "
        f"ResourceNotFoundException (no residual state from the failed Sample), got {reward_code}"
    )
    assert reward_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {reward_message!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected (no backing job/trajectory exists), "
        f"but it SUCCEEDED and returned {result!r}"
    )


def _job_arn(ctx, account_id, job_name=None, job_type="AgentRFT"):
    name = job_name or ctx.unique_name("sim2real-sjr-job-")
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/{job_type}/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
