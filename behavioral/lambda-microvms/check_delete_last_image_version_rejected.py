"""delete-last-image-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-last-image-version-rejected"
GROUP = "image-version-lifecycle"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMicrovmImageVersion refuses an image's only version with ValidationException (not the
    model's ConflictException); the version survives unchanged and deleting the image is accepted.
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    name = ctx.unique_name("sim2real-behav-mvm-")

    created = _create_image_retrying(
        mvm,
        name=name, baseImageArn=base,
        buildRoleArn=_own_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-check": CHECK},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    # A CREATING image refuses every mutation; settle first so the refusal under test is the
    # last-version rule and not the in-flight-state rule.
    _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 240)
    before = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)

    error = _client_error(
        lambda: mvm.delete_microvm_image_version(
            imageIdentifier=image_arn, imageVersion=version
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"deleting the only version answered {error!r}, expected ValidationException"
    )
    assert error.get("Message") == "This is the last version. Please delete the entire image", error

    # EFFECT ABSENT: the version is still there, in the state it was in.
    versions = _all_versions(mvm, image_arn)
    assert [v["imageVersion"] for v in versions] == [version], (
        f"the refused delete left versions {[v['imageVersion'] for v in versions]!r}, "
        f"expected [{version!r}]"
    )
    after = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert (after["state"], after["status"]) == (before["state"], before["status"]), (
        f"the refused delete moved the version from "
        f"{(before['state'], before['status'])!r} to {(after['state'], after['status'])!r}"
    )

    # POSITIVE CONTROL: the remedy the error names is accepted on the same resource.
    deleted = mvm.delete_microvm_image(imageIdentifier=image_arn)
    assert deleted["state"] == "DELETING", (
        f"DeleteMicrovmImage returned state {deleted['state']!r}, expected DELETING"
    )

    # TERMINAL READ: confirm the accepted delete independently of the mutating call's response.
    try:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        assert seen["state"] in {"DELETING", "DELETED"}, (
            f"an independent read after the accepted delete showed state {seen['state']!r}, "
            f"expected DELETING or DELETED"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"an independent read after the accepted delete raised {exc.response['Error']['Code']!r}, "
            f"expected ResourceNotFoundException or a DELETING/DELETED state"
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


def _client_error(fn) -> dict:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


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


def _all_customer_images(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_images(**kw, **({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _all_versions(mvm, image_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_image_versions(
            imageIdentifier=image_arn, **({"nextToken": token} if token else {})
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
