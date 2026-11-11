"""concurrent-update-reward-notfound-consistency."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-reward-notfound-consistency"
GROUP = "concurrency"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Many concurrent UpdateReward calls on the same never-created JobArn and TrajectoryId each return
    the identical ResourceNotFoundException outcome, never a success or a ConflictException.
    """
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    job_arn = _job_arn(ctx, account_id)
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    client = ctx.client("sagemakerjobruntime")

    racer_count = 8

    def _racer(i: int):
        try:
            client.update_reward(
                JobArn=job_arn, TrajectoryId=trajectory_id, Rewards=[float(i)]
            )
            return "success", None
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message")

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        outcomes = [f.result() for f in as_completed(futures)]

    assert len(outcomes) == racer_count, (
        f"expected {racer_count} racer outcomes, got {len(outcomes)}: {outcomes}"
    )
    want = ("ResourceNotFoundException", f"Trajectory {trajectory_id} not found for account {account_id}")
    for outcome in outcomes:
        assert outcome == want, (
            f"expected every concurrent racer against a never-created job to get "
            f"{want!r} independently, got {outcome!r} among {outcomes}"
        )


def _job_arn(ctx, account_id, job_name=None, job_type="AgentRFT"):
    name = job_name or ctx.unique_name("sim2real-sjr-job-")
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/{job_type}/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
