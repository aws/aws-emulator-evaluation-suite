"""image-build-failure-surfaces-state-reason-on-every-build."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-build-failure-surfaces-state-reason-on-every-build"
GROUP = "image-build-fanout"
SERVICES = ["lambda-microvms"]

_MISSING_BUCKET_REASON = "The S3 bucket does not exist."


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A failed build settles image CREATE_FAILED (latestFailedImageVersion only), version
    FAILED/INACTIVE and every build FAILED, with one stateReason on the version and each build.
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    name = ctx.unique_name("sim2real-behav-mvm-")

    created = _create_image_retrying(
        mvm,
        name=name,
        baseImageArn=base,
        buildRoleArn=_own_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-check": CHECK},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]
    assert created["state"] == "CREATING", (
        f"CreateMicrovmImage returned state {created['state']!r}, expected CREATING"
    )

    image = _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 240)
    assert image["state"] == "CREATE_FAILED", (
        f"image settled in {image['state']!r}; this artifact cannot be fetched so the build "
        f"must fail"
    )
    assert image.get("latestFailedImageVersion") == version, (
        f"image reports latestFailedImageVersion "
        f"{image.get('latestFailedImageVersion')!r}, expected {version!r}"
    )
    assert "latestActiveImageVersion" not in image, (
        f"image exposes latestActiveImageVersion "
        f"{image.get('latestActiveImageVersion')!r} although no build ever succeeded"
    )

    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert ver["state"] == "FAILED", (
        f"version state is {ver['state']!r} while the image is CREATE_FAILED"
    )
    assert ver["status"] == "INACTIVE", (
        f"version status is {ver['status']!r}; a version whose build failed must not be ACTIVE"
    )
    assert ver.get("stateReason") == _MISSING_BUCKET_REASON, (
        f"version stateReason is {ver.get('stateReason')!r}, expected "
        f"{_MISSING_BUCKET_REASON!r}"
    )

    builds = _all_builds(mvm, image_arn, version)
    assert builds, "the failed version exposes no build records at all"
    for b in builds:
        assert b["buildState"] == "FAILED", (
            f"build {b['buildId']!r} (generation {b['chipsetGeneration']!r}) is "
            f"{b['buildState']!r} while the version is FAILED"
        )
        assert b.get("stateReason") == _MISSING_BUCKET_REASON, (
            f"build {b['buildId']!r} stateReason is {b.get('stateReason')!r}, expected "
            f"{_MISSING_BUCKET_REASON!r}"
        )
        detail = mvm.get_microvm_image_build(
            imageIdentifier=image_arn, imageVersion=version, buildId=b["buildId"]
        )
        assert "snapshotBuild" not in detail, (
            f"build {b['buildId']!r} carries snapshotBuild {detail.get('snapshotBuild')!r} "
            f"although it FAILED"
        )




def _own_build_role(ctx) -> str:
    """A build role this check creates and deletes. The code artifact is absent, so the build
    fails before the role's permissions matter; the role only has to exist and trust Lambda."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_own_role(iam, role_name))
    return role_arn


def _delete_own_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_image_retrying(mvm, budget: float = 90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while a just-created build role is still propagating."""
    deadline = time.time() + budget
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = err["Code"] == "AccessDeniedException" or "role" in err.get("Message", "").lower()
            if not propagating or time.time() >= deadline:
                raise
            time.sleep(5)


def _managed_base_image(mvm) -> str:
    arns: list[str] = []
    token = None
    while True:
        page = mvm.list_managed_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        arns.extend(i["imageArn"] for i in items)
        token = page.get("nextToken")
        if not token or not items:
            break
    assert arns, "ListManagedMicrovmImages returned no managed base image to build from"
    return sorted(arns)[0]


def _all_builds(mvm, image_arn: str, version: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_image_builds(
            imageIdentifier=image_arn,
            imageVersion=version,
            **({"nextToken": token} if token else {}),
        )
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _await_image_state(mvm, image_arn: str, wanted: set[str], budget: float) -> dict:
    deadline = time.time() + budget
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        if seen["state"] in wanted:
            return seen
        time.sleep(5)
    raise AssertionError(
        f"image {image_arn!r} never reached one of {sorted(wanted)!r} within {budget}s; "
        f"last state was {(seen or {}).get('state')!r}"
    )


def _delete_image(mvm, image_arn: str) -> None:
    deadline = time.time() + 150
    while True:
        try:
            mvm.delete_microvm_image(imageIdentifier=image_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.time() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
