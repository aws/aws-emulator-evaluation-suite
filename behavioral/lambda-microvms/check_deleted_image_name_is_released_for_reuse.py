"""deleted-image-name-is-released-for-reuse."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-image-name-is-released-for-reuse"
GROUP = "image-naming"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Image deletion is asynchronous: the image reads DELETING until it 404s and leaves the list, and
    the name is reusable; the replacement gets the same name-derived ARN with a later createdAt.
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    role = _own_build_role(ctx)
    name = ctx.unique_name("sim2real-behav-mvm-")

    first = _create_image_retrying(
        mvm,
        name=name, baseImageArn=base, buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
    )
    image_arn = first["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    first_created_at = first["createdAt"]

    _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 240)
    deleting = mvm.delete_microvm_image(imageIdentifier=image_arn)
    assert deleting["state"] == "DELETING", (
        f"DeleteMicrovmImage returned {deleting['state']!r}, expected DELETING"
    )
    # Real AWS keeps the image readable in DELETING for about a minute; a target that finishes
    # the delete first answers not found, which the absence wait below grades.
    try:
        still_there = mvm.get_microvm_image(imageIdentifier=image_arn)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"immediately after the delete, GetMicrovmImage raised {exc.response['Error']!r}"
        )
    else:
        assert still_there["state"] == "DELETING", (
            f"immediately after the delete the image reads {still_there['state']!r}, expected "
            f"DELETING"
        )

    # DELETING to gone takes about a minute.
    _await_absent(mvm, image_arn, 180)
    assert not [i for i in _all_customer_images(mvm) if i["name"] == name], (
        f"the image named {name!r} is gone from GetMicrovmImage but still in ListMicrovmImages"
    )
    # The DeleteMicrovmImage model doc calls a re-delete of a deleted image idempotent ("succeeds
    # without error"); real AWS answers ResourceNotFoundException once the image is gone.
    dead_delete = _client_error(lambda: mvm.delete_microvm_image(imageIdentifier=image_arn))
    assert dead_delete.get("Code") == "ResourceNotFoundException", (
        f"DeleteMicrovmImage on the already-gone {image_arn!r} returned {dead_delete!r}, "
        f"expected ResourceNotFoundException"
    )
    assert dead_delete.get("Message") == f"MicroVM image not found: {image_arn}", dead_delete

    second = _create_image_retrying(
        mvm,
        name=name, baseImageArn=base, buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
    )
    ctx.on_cleanup(lambda: _delete_image(mvm, second["imageArn"]))
    assert second["imageArn"] == image_arn, (
        f"the replacement image got ARN {second['imageArn']!r}; this service derives the ARN "
        f"from the name, so it must be {image_arn!r}"
    )
    assert second["createdAt"] > first_created_at, (
        f"the replacement reports createdAt {second['createdAt']!r}, not after the original's "
        f"{first_created_at!r} -- the record was reused rather than recreated"
    )
    assert second["state"] == "CREATING", (
        f"the replacement image starts in {second['state']!r}, expected CREATING"
    )

    confirmed = mvm.get_microvm_image(imageIdentifier=image_arn)
    assert confirmed["imageArn"] == image_arn, (
        f"an independent GetMicrovmImage on {image_arn!r} reports imageArn "
        f"{confirmed['imageArn']!r}; the create response's own echo cannot be trusted alone"
    )
    assert confirmed["createdAt"] > first_created_at, (
        f"an independent GetMicrovmImage on {image_arn!r} reports createdAt "
        f"{confirmed['createdAt']!r}, not after the original's {first_created_at!r}"
    )


def _await_absent(mvm, image_arn: str, budget: float) -> None:
    deadline = time.time() + budget
    last = None
    while time.time() < deadline:
        try:
            last = mvm.get_microvm_image(imageIdentifier=image_arn)["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(
        f"image {image_arn!r} was still readable after {budget}s of deletion; last state "
        f"{last!r}"
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
