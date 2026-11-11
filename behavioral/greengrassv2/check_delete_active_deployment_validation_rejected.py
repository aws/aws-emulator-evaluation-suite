"""delete-active-deployment-validation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-active-deployment-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeployment on an ACTIVE deployment is rejected with ValidationException; canceling first lets the delete succeed."""
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    thing_name = ctx.unique_name("sim2real-ggv2-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{thing_name}"

    deployment_id = ggv2.create_deployment(targetArn=target_arn, tags={"env": "sim2real"})["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))

    initial_status = ggv2.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
    assert initial_status == "ACTIVE", f"expected ACTIVE right after create, got {initial_status!r}"

    code, message = _error_code(lambda: ggv2.delete_deployment(deploymentId=deployment_id))
    assert code == "ValidationException", f"expected ValidationException deleting an ACTIVE deployment, got {code!r}"
    expected = "Invalid Input: Greengrass deployment must be canceled before deletion"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the deployment record is still there, unaffected.
    still_there = ggv2.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
    assert still_there == "ACTIVE", f"delete should have been a no-op, but status is now {still_there!r}"

    # Positive control: cancel first, then delete succeeds.
    ggv2.cancel_deployment(deploymentId=deployment_id)
    status = _poll_until_status(ggv2, deployment_id, {"CANCELED"}, timeout_s=45.0)
    assert status == "CANCELED", f"expected CANCELED after cancel_deployment, got {status!r}"

    ggv2.delete_deployment(deploymentId=deployment_id)
    final_code, final_message = _error_code(lambda: ggv2.get_deployment(deploymentId=deployment_id))
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted deployment, got {final_code!r}"
    )
    assert final_message == "Deployment not found", final_message


def _poll_until_status(ggv2, deployment_id: str, terminal: set, timeout_s: float, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ggv2.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise TimeoutError(f"deployment {deployment_id} did not reach {terminal} within {timeout_s}s, last status={status!r}")


def _cleanup_deployment(ggv2, deployment_id: str) -> None:
    _try(lambda: ggv2.cancel_deployment(deploymentId=deployment_id))
    _try(lambda: ggv2.delete_deployment(deploymentId=deployment_id))


def _try(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
