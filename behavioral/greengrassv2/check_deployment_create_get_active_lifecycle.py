"""deployment-create-get-active-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-create-get-active-lifecycle"
GROUP = "deployment-lifecycle"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment against an IoT thing group produces an ACTIVE deployment that carries
    the requested component version, is the latest for its target, and is discoverable via
    both GetDeployment and ListDeployments."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    group = iot.create_thing_group(
        thingGroupName=group_name,
        tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )
    group_arn = group["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    comp_name = ctx.unique_name("sim2real-ggv2-depcomp-")
    comp_version = "1.0.0"
    comp = gg.create_component_version(
        inlineRecipe=_make_recipe(comp_name, comp_version),
        tags={"sim2real-purpose": "behavioral-check"},
    )
    comp_arn = comp["arn"]
    ctx.on_cleanup(lambda: _delete_component_ignore_missing(gg, comp_arn))
    _poll_until(
        lambda: gg.describe_component(arn=comp_arn)["status"]["componentState"],
        lambda s: s in ("DEPLOYABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    dep = gg.create_deployment(
        targetArn=group_arn,
        components={comp_name: {"componentVersion": comp_version}},
        tags={"sim2real-purpose": "behavioral-check"},
    )
    deployment_id = dep["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, deployment_id))

    got = gg.get_deployment(deploymentId=deployment_id)
    assert got["targetArn"] == group_arn, (
        f"expected targetArn={group_arn!r}, got {got['targetArn']!r}"
    )
    assert got["deploymentStatus"] == "ACTIVE", (
        f"expected deploymentStatus=ACTIVE, got {got['deploymentStatus']!r}"
    )
    assert got["isLatestForTarget"] is True, (
        f"expected isLatestForTarget=True, got {got['isLatestForTarget']!r}"
    )
    assert got["components"][comp_name]["componentVersion"] == comp_version, (
        f"expected components[{comp_name!r}].componentVersion={comp_version!r}, "
        f"got {got['components'][comp_name]['componentVersion']!r}"
    )

    listed = gg.list_deployments(targetArn=group_arn, historyFilter="LATEST_ONLY")["deployments"]
    assert any(d["deploymentId"] == deployment_id for d in listed), (
        f"expected deploymentId={deployment_id!r} in ListDeployments(LATEST_ONLY) result, "
        f"got ids={[d['deploymentId'] for d in listed]!r}"
    )


# ===== helpers =====
def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "deployment lifecycle test component",
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


def _delete_component_ignore_missing(gg, arn: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
