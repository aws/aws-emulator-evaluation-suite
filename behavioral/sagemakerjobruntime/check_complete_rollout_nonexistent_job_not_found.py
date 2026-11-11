"""complete-rollout-nonexistent-job-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-rollout-nonexistent-job-not-found"
GROUP = "not-found"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteRollout on a well-formed but nonexistent JobArn and TrajectoryId returns
    ResourceNotFoundException with its exact message rather than sealing a trajectory that never
    existed.
    """
    account_id = ctx.account
    job_arn = _job_arn(ctx, account_id)
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")

    client = ctx.client("sagemakerjobruntime")

    def _call():
        return client.complete_rollout(JobArn=job_arn, TrajectoryId=trajectory_id)

    code, message = _error_code(_call)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Trajectory {trajectory_id} not found for account {account_id}"
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
