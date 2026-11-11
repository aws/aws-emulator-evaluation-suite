"""update-image-while-creating-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-image-while-creating-rejected"
GROUP = "image-version-lifecycle"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMicrovmImage is refused with ValidationException while the image is CREATING.

    The refusal adds no version; once the build settles the same call is accepted (UPDATING, v2).
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    role = _own_build_role(ctx)
    # The build settles on its own clock. An update that is accepted may have landed after the
    # image left CREATING, so that image is set aside and the refusal is retried on a fresh one.
    error = image_arn = artifact = None
    for _ in range(5):
        name = ctx.unique_name("sim2real-behav-mvm-")
        artifact = {"uri": f"s3://{name}-absent/code.zip"}
        created = _create_image_retrying(
            mvm,
            name=name, baseImageArn=base, buildRoleArn=role, codeArtifact=artifact,
            description="first", tags={"sim2real-check": CHECK},
        )
        image_arn = created["imageArn"]
        ctx.on_cleanup(lambda arn=image_arn: _delete_image(mvm, arn))
        assert created["state"] == "CREATING", (
            f"CreateMicrovmImage returned {created['state']!r}; this check needs an in-flight image"
        )
        error = _error_or_none(
            lambda: mvm.update_microvm_image(
                imageIdentifier=image_arn, baseImageArn=base, buildRoleArn=role,
                codeArtifact=artifact, description="second",
            )
        )
        if error is not None:
            break
    assert error is not None, (
        "UpdateMicrovmImage was accepted on every fresh image, expected ValidationException "
        "while the image is CREATING"
    )
    assert error.get("Code") == "ValidationException", (
        f"UpdateMicrovmImage on a CREATING image answered {error!r}, expected ValidationException"
    )
    assert error.get("Message") == f"Cannot update MicroVM Image in its current state: {image_arn}", error

    # EFFECT ABSENT: no second version, and the description was not rewritten.
    versions = _all_versions(mvm, image_arn)
    assert len(versions) == 1, (
        f"the refused update left {len(versions)} versions "
        f"{[v['imageVersion'] for v in versions]!r}, expected 1"
    )
    assert versions[0].get("description") == "first", (
        f"the refused update changed the version description to "
        f"{versions[0].get('description')!r}, expected 'first'"
    )

    # POSITIVE CONTROL: the same call succeeds once the image has settled.
    _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, _budget_s(ctx, 240), ctx=ctx)
    updated = mvm.update_microvm_image(
        imageIdentifier=image_arn, baseImageArn=base, buildRoleArn=role,
        codeArtifact=artifact, description="second",
    )
    assert updated["state"] == "UPDATING", (
        f"the accepted update returned state {updated['state']!r}, expected UPDATING"
    )
    assert updated["imageVersion"] != versions[0]["imageVersion"], (
        f"the accepted update reused version {updated['imageVersion']!r} instead of minting a "
        f"new one"
    )

    # Re-read through a different operation than the one that minted the version.
    versions_after = _all_versions(mvm, image_arn)
    version_ids_after = {v["imageVersion"] for v in versions_after}
    assert len(versions_after) == 2, (
        f"ListMicrovmImageVersions shows {len(versions_after)} versions "
        f"{sorted(version_ids_after)!r} after the accepted update, expected 2"
    )
    assert updated["imageVersion"] in version_ids_after, (
        f"the accepted update's new version {updated['imageVersion']!r} is not visible via "
        f"ListMicrovmImageVersions, which returned {sorted(version_ids_after)!r}"
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
            time.sleep(2)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_or_none(fn) -> dict | None:
    """The Error of the ClientError fn() raises, or None when the call is accepted."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return None


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


def _await_image_state(mvm, image_arn: str, wanted: set[str], budget: float, ctx=None) -> dict:
    deadline = time.monotonic() + budget
    seen = None
    while True:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        if seen["state"] in wanted:
            return seen
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"image {image_arn!r} to reach one of {sorted(wanted)!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"image {image_arn!r} never reached one of {sorted(wanted)!r} within {budget:.0f}s; "
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
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
