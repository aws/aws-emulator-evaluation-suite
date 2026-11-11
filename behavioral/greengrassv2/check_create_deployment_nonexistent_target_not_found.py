"""create-deployment-nonexistent-target-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-nonexistent-target-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment on a never-created thing ARN raises ValidationException ("Invalid Input:
    Target not found") and records no deployment, while on a real thing it creates an ACTIVE
    deployment.
    """
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bogus_thing = ctx.unique_name("sim2real-ggv2-missing-thing-")
    bogus_target = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{bogus_thing}"

    code, message = _error_code(lambda: ggv2.create_deployment(targetArn=bogus_target))
    assert code == "ValidationException", f"got code={code!r}"
    assert message == "Invalid Input: Target not found", message

    # Effect absent: no deployment record was created against the bogus target.
    deployments = ggv2.list_deployments(targetArn=bogus_target, historyFilter="ALL")["deployments"]
    assert deployments == [], deployments

    # Positive control: the identical call against a real, existing thing succeeds.
    real_thing_name = ctx.unique_name("sim2real-ggv2-real-thing-")
    iot.create_thing(thingName=real_thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=real_thing_name))
    real_target = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{real_thing_name}"

    created = ggv2.create_deployment(targetArn=real_target)
    deployment_id = created["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))
    fetched = ggv2.get_deployment(deploymentId=deployment_id)
    assert fetched["deploymentStatus"] == "ACTIVE", fetched["deploymentStatus"]


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


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS accepted this call, but it should have been rejected; got {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
