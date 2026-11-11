"""get-deployment-nonexistent-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployment succeeds for a real deployment (positive control), but for a
    deploymentId that was never created it returns ResourceNotFoundException."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    target_arn = iot.create_thing_group(
        thingGroupName=group_name, tags=[{"Key": "sim2real", "Value": "behavioral"}]
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    comp_name = ctx.unique_name("sim2real-ggv2-notfoundcomp-")
    comp_arn = gg.create_component_version(
        inlineRecipe=_make_recipe(comp_name, "1.0.0"), tags={"sim2real": "behavioral"}
    )["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, comp_arn))
    _poll_until(
        lambda: gg.describe_component(arn=comp_arn)["status"]["componentState"],
        lambda s: s in ("DEPLOYABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    created = gg.create_deployment(
        targetArn=target_arn,
        components={comp_name: {"componentVersion": "1.0.0"}},
        tags={"sim2real": "behavioral"},
    )
    deployment_id = created["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, deployment_id))

    # Positive control: GetDeployment resolves a real deployment before we assert it
    # rejects a fabricated one — otherwise a target that rejects every GetDeployment
    # call would pass this check for free.
    real = gg.get_deployment(deploymentId=deployment_id)
    assert real["deploymentId"] == deployment_id, (
        f"expected positive-control deploymentId {deployment_id!r}, "
        f"got {real.get('deploymentId')!r}"
    )

    fake_id = ctx.unique_name("sim2real-ggv2-missing-deployment-")
    code, message = _client_error(lambda: gg.get_deployment(deploymentId=fake_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for nonexistent deploymentId {fake_id!r}, "
        f"got {code!r}"
    )
    assert message == "Deployment not found", f"got message={message!r}"


# ===== helpers =====
def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "get-deployment not-found test component",
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_deployment(gg, deployment_id: str) -> None:
    deadline = time.monotonic() + 15.0
    try:
        gg.cancel_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        # A deployment that is not ACTIVE cannot be canceled; DeleteDeployment decides.
        if code not in ("ConflictException", "ValidationException"):
            raise
    while True:
        try:
            gg.delete_deployment(deploymentId=deployment_id)
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


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
