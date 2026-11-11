"""concurrent-create-deployment-same-target-single-latest."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-deployment-same-target-single-latest"
GROUP = "concurrency"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateDeployment calls on one target either succeed with distinct ids or raise
    ConflictException, and they settle to exactly one of them isLatestForTarget=True, also in
    ListDeployments LATEST_ONLY.
    """
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    thing_name = ctx.unique_name("sim2real-ggv2-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{thing_name}"

    def attempt(_):
        try:
            return ggv2.create_deployment(targetArn=target_arn)["deploymentId"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ConflictException":
                return None
            raise

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))

    deployment_ids = [d for d in results if d is not None]
    for deployment_id in deployment_ids:
        ctx.on_cleanup(lambda d=deployment_id: _cleanup_deployment(ggv2, d))

    assert len(deployment_ids) >= 1, "expected at least one concurrent CreateDeployment to succeed"
    assert len(set(deployment_ids)) == len(deployment_ids), "expected distinct deployment ids"

    latest_id = _poll_until_single_latest(ggv2, target_arn, deployment_ids, timeout_s=45.0)
    assert latest_id in deployment_ids, f"latest_id {latest_id} not among our own {deployment_ids}"

    for deployment_id in deployment_ids:
        status = ggv2.get_deployment(deploymentId=deployment_id)
        if deployment_id == latest_id:
            assert status["isLatestForTarget"] is True, (
                f"expected winning deployment {deployment_id} isLatestForTarget=True, got {status}"
            )
        else:
            assert status["isLatestForTarget"] is False, status


def _poll_until_single_latest(ggv2, target_arn: str, deployment_ids, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        latest = ggv2.list_deployments(targetArn=target_arn, historyFilter="LATEST_ONLY")["deployments"]
        latest_ids = [d["deploymentId"] for d in latest if d["deploymentId"] in deployment_ids]
        if len(latest_ids) == 1:
            return latest_ids[0]
        time.sleep(interval_s)
    raise AssertionError(f"never settled to exactly one latest deployment, saw {latest_ids}")


def _cleanup_deployment(ggv2, deployment_id: str) -> None:
    """Cancel then delete the deployment; gone already counts, other refusals raise."""
    deadline = time.monotonic() + 15.0
    try:
        ggv2.cancel_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        # A deployment that is not ACTIVE cannot be canceled; DeleteDeployment decides.
        if code not in ("ConflictException", "ValidationException"):
            raise
    while True:
        try:
            ggv2.delete_deployment(deploymentId=deployment_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # DeleteDeployment refuses until the cancel has taken effect; retry only that refusal.
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
