"""create-deployment-invalid-failure-handling-policy-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-invalid-failure-handling-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment with a failureHandlingPolicy outside ROLLBACK/DO_NOTHING raises
    ValidationException with the exact message and creates no deployment, while the identical
    call with a valid policy succeeds.
    """
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-ggv2-devicetgt-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = f"arn:aws:iot:{ctx.region}:{ctx.account}:thing/{thing_name}"

    code, message = _error_code(
        lambda: ggv2.create_deployment(
            targetArn=target_arn,
            deploymentPolicies={"failureHandlingPolicy": "NOT_A_REAL_POLICY"},
        )
    )
    assert code == "ValidationException", f"got code={code!r}"
    expected = (
        "1 validation error detected: Value 'NOT_A_REAL_POLICY' at "
        "'deploymentPolicies.failureHandlingPolicy' failed to satisfy constraint: Member must "
        "satisfy enum value set: [ROLLBACK, DO_NOTHING]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    deployments = ggv2.list_deployments(targetArn=target_arn, historyFilter="ALL")["deployments"]
    assert deployments == [], f"expected no deployment recorded against the invalid policy, got {deployments}"

    # Positive control: the identical call with a valid policy succeeds.
    created = ggv2.create_deployment(
        targetArn=target_arn, deploymentPolicies={"failureHandlingPolicy": "DO_NOTHING"}
    )
    deployment_id = created["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))
    fetched = ggv2.get_deployment(deploymentId=deployment_id)
    assert fetched["deploymentStatus"] == "ACTIVE", f"got {fetched['deploymentStatus']!r}"


def _cleanup_deployment(ggv2, deployment_id: str) -> None:
    deadline = time.monotonic() + 15.0
    try:
        ggv2.cancel_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
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
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS accepted this call, but it should have been rejected; got {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
