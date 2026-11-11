"""cancel-deployment-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-deployment-nonexistent-not-found"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelDeployment against a deploymentId that was never created raises ResourceNotFoundException,
    while canceling a real, currently ACTIVE deployment (the positive control) succeeds and
    transitions it to CANCELED."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    bogus_id = ctx.unique_name("sim2real-gg-nodeployment-")
    code, message = _error_code(lambda: gg.cancel_deployment(deploymentId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Deployment not found", f"expected message 'Deployment not found', got {message!r}"

    # positive control: canceling a real ACTIVE deployment succeeds
    thing_name = ctx.unique_name("sim2real-gg-cancelctrl-")
    thing = iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    dep = gg.create_deployment(targetArn=thing["thingArn"])
    deployment_id = dep["deploymentId"]
    ctx.on_cleanup(lambda: _safe_delete_deployment(ctx, deployment_id))

    gg.cancel_deployment(deploymentId=deployment_id)
    final_status = _poll_until(
        lambda: gg.get_deployment(deploymentId=deployment_id)["deploymentStatus"],
        lambda status: status == "CANCELED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final_status == "CANCELED", f"expected CANCELED after cancel, got {final_status!r}"


def _safe_delete_deployment(ctx, deployment_id: str) -> None:
    gg = ctx.client("greengrassv2")
    try:
        gg.delete_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
