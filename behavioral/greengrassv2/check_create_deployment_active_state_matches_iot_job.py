"""create-deployment-active-state-matches-iot-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-active-state-matches-iot-job"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment starts an ACTIVE deployment backed by a real, resolvable IoT job."""
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    target_arn = iot.create_thing_group(
        thingGroupName=group_name, tags=[{"Key": "env", "Value": "sim2real"}]
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    comp_name = ctx.unique_name("sim2real-ggv2-jobcomp-")
    comp_arn = ggv2.create_component_version(
        inlineRecipe=_make_recipe(comp_name, "1.0.0"), tags={"env": "sim2real"}
    )["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(ggv2, comp_arn))
    _poll_until(
        lambda: ggv2.describe_component(arn=comp_arn)["status"]["componentState"],
        lambda s: s in ("DEPLOYABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    dep_name = ctx.unique_name("sim2real-ggv2-dep-")
    created = ggv2.create_deployment(
        targetArn=target_arn,
        deploymentName=dep_name,
        components={comp_name: {"componentVersion": "1.0.0"}},
        tags={"env": "sim2real"},
    )
    deployment_id = created["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))

    assert created.get("iotJobId"), f"CreateDeployment response missing iotJobId; keys={list(created.keys())!r}"
    assert created.get("iotJobArn"), f"CreateDeployment response missing iotJobArn; keys={list(created.keys())!r}"

    fetched = ggv2.get_deployment(deploymentId=deployment_id)
    assert fetched["targetArn"] == target_arn, (
        f"GetDeployment targetArn mismatch: expected={target_arn!r} actual={fetched['targetArn']!r}"
    )
    assert fetched["deploymentStatus"] == "ACTIVE", (
        f"expected deploymentStatus=ACTIVE, got {fetched['deploymentStatus']!r}"
    )
    # GetDeployment doesn't always echo iotJobId/iotJobArn back (observed empirically), so
    # verify the job identity from the CreateDeployment response instead.
    if fetched.get("iotJobId"):
        assert fetched["iotJobId"] == created["iotJobId"], (
            f"GetDeployment iotJobId {fetched['iotJobId']!r} != CreateDeployment iotJobId {created['iotJobId']!r}"
        )
        assert fetched["iotJobArn"] == created["iotJobArn"], (
            f"GetDeployment iotJobArn {fetched['iotJobArn']!r} != CreateDeployment iotJobArn {created['iotJobArn']!r}"
        )

    # The deployment must be backed by a genuine IoT job, not a fabricated identifier.
    job = iot.describe_job(jobId=created["iotJobId"])["job"]
    assert job["jobArn"] == created["iotJobArn"], (
        f"IoT job arn {job['jobArn']!r} != CreateDeployment iotJobArn {created['iotJobArn']!r}"
    )
    assert job["status"] in ("IN_PROGRESS", "QUEUED"), (
        f"expected IoT job status IN_PROGRESS or QUEUED, got {job['status']!r}"
    )


# ===== helpers =====

def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "iot job identity test component",
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


def _delete_ignore_missing(ggv2, arn: str) -> None:
    try:
        ggv2.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

