"""delete-component-in-use-by-active-deployment-lenient."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-in-use-by-active-deployment-lenient"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteComponent on a version referenced by an ACTIVE deployment succeeds and removes it from
    the registry: AWS does not block the delete, existing deployments referencing it subsequently
    fail instead."""
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-ggv2-comp-")
    in_use_arn = ggv2.create_component_version(
        inlineRecipe=json.dumps(_recipe(name, "1.0.0")).encode("utf-8")
    )["arn"]
    _poll_until_deployable(ggv2, in_use_arn)
    ctx.on_cleanup(lambda: _try(lambda: ggv2.delete_component(arn=in_use_arn)))

    thing_name = ctx.unique_name("sim2real-ggv2-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{thing_name}"

    deployment_id = ggv2.create_deployment(
        targetArn=target_arn,
        components={name: {"componentVersion": "1.0.0"}},
    )["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))

    status = ggv2.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
    assert status == "ACTIVE", f"expected the deployment to still be ACTIVE before delete, got {status!r}"

    # Real AWS allows this even though the deployment is still ACTIVE and references it.
    ggv2.delete_component(arn=in_use_arn)
    deleted_code, deleted_message = _poll_until_rejected(
        lambda: ggv2.describe_component(arn=in_use_arn), timeout_s=30, interval_s=2
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected DescribeComponent on the deleted in-use version to 404, got code={deleted_code!r}"
    )
    expected = f"Component ({name}:1.0.0) does not exist in account {account_id}."
    assert deleted_message == expected, f"expected message {expected!r}, got {deleted_message!r}"

    # A mutation on the now-dead id is rejected too, not just a read. TagResource's own
    # not-found code differs from GetComponent/DescribeComponent's (measured on real AWS).
    mutate_code, mutate_message = _client_error(
        lambda: ggv2.tag_resource(resourceArn=in_use_arn, tags={"probe": "x"})
    )
    assert mutate_code == "NotFoundException", (
        f"expected TagResource on the deleted component to be rejected as not-found, got code={mutate_code!r}"
    )
    assert mutate_message == "Resource was not found", f"got message={mutate_message!r}"

    # Positive control: an unrelated, unreferenced component version deletes cleanly too.
    other_name = ctx.unique_name("sim2real-ggv2-comp-")
    other_arn = ggv2.create_component_version(
        inlineRecipe=json.dumps(_recipe(other_name, "1.0.0")).encode("utf-8")
    )["arn"]
    ggv2.delete_component(arn=other_arn)
    other_code, other_message = _client_error(lambda: ggv2.get_component(arn=other_arn))
    assert other_code == "ResourceNotFoundException", (
        f"expected GetComponent on the unrelated deleted version to 404, got code={other_code!r}"
    )
    expected = f"PRIVATE component ({other_name}:1.0.0) under account {account_id} does not exist"
    assert other_message == expected, f"expected message {expected!r}, got {other_message!r}"


# ===== helpers =====

def _recipe(name: str, version: str) -> dict:
    return {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }


def _poll_until_deployable(ggv2, arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = ggv2.describe_component(arn=arn)["status"]["componentState"]
        if state == "DEPLOYABLE":
            return
        if state == "FAILED":
            raise AssertionError("component reached FAILED state instead of DEPLOYABLE")
        time.sleep(interval_s)
    raise AssertionError("component never reached DEPLOYABLE")


def _poll_until_rejected(fn, timeout_s=60.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message); a call that keeps
    succeeding past the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"call still succeeded after {timeout_s}s, last result={result!r}")
        time.sleep(interval_s)


def _cleanup_deployment(ggv2, deployment_id: str) -> None:
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
            # DeleteDeployment refuses ("must be canceled before deletion") until the cancel
            # has taken effect; retry only that refusal.
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _try(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

