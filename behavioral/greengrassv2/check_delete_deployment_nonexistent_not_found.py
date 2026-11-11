"""delete-deployment-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-deployment-nonexistent-not-found"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDeployment for a deploymentId that was never created is rejected with
    ResourceNotFoundException; a real deployment (after being canceled) still deletes."""
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    fake_id = ctx.unique_name("sim2real-ggv2-missing-deployment-")
    code, message = _error_code(lambda: ggv2.delete_deployment(deploymentId=fake_id))
    assert code == "ResourceNotFoundException", code
    assert message == "Deployment not found", message

    # Positive control: a real deployment, canceled first, deletes successfully.
    thing_name = ctx.unique_name("sim2real-ggv2-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{thing_name}"

    deployment_id = ggv2.create_deployment(targetArn=target_arn)["deploymentId"]
    ctx.on_cleanup(lambda: _try(lambda: ggv2.delete_deployment(deploymentId=deployment_id)))

    ggv2.cancel_deployment(deploymentId=deployment_id)
    status = _poll_until_status(ggv2, deployment_id, {"CANCELED"}, timeout_s=45.0)
    assert status == "CANCELED", status

    ggv2.delete_deployment(deploymentId=deployment_id)
    get_code, get_message = _error_code(lambda: ggv2.get_deployment(deploymentId=deployment_id))
    assert get_code == "ResourceNotFoundException", get_code
    assert get_message == "Deployment not found", get_message

    # Deletes prove gone and unusable: a mutation on the now-dead id also fails.
    cancel_code, cancel_message = _error_code(lambda: ggv2.cancel_deployment(deploymentId=deployment_id))
    assert cancel_code == "ResourceNotFoundException", cancel_code
    assert cancel_message == "Deployment not found", cancel_message


def _poll_until_status(ggv2, deployment_id: str, terminal: set, timeout_s: float, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ggv2.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"deployment {deployment_id} did not reach {terminal} within {timeout_s}s, last={status!r}")


def _try(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
