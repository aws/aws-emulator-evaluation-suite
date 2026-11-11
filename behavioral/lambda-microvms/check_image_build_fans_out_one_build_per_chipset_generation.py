"""image-build-fans-out-one-build-per-chipset-generation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-build-fans-out-one-build-per-chipset-generation"
GROUP = "image-build-fanout"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One CreateMicrovmImage fans out into one ARM_64/GRAVITON build per chipset generation, with
    distinct buildIds, and GetMicrovmImageBuild matches each ListMicrovmImageBuilds summary.
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    name = ctx.unique_name("sim2real-behav-mvm-")

    created = _create_image_once_role_is_visible(mvm,
        name=name,
        baseImageArn=base,
        buildRoleArn=_create_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-origin": "create"},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    builds = _all_builds(mvm, image_arn, version)
    assert len(builds) >= 2, (
        f"one create produced {len(builds)} build record(s) {[b['buildId'] for b in builds]!r}; "
        f"real AWS fans out to one per chipset generation"
    )

    generations = sorted(b["chipsetGeneration"] for b in builds)
    assert len(set(generations)) == len(generations), (
        f"chipset generations {generations!r} contain a duplicate — the fan-out must be one "
        f"build per generation"
    )
    assert all(isinstance(g, str) and g.isdigit() for g in generations), (
        f"builds covered chipset generations {generations!r}, expected numeric generation strings"
    )

    ids = [b["buildId"] for b in builds]
    assert len(set(ids)) == len(ids), f"buildIds are not distinct: {ids!r}"

    for b in builds:
        assert b["architecture"] == "ARM_64", (
            f"build {b['buildId']!r} reports architecture {b['architecture']!r}, expected ARM_64"
        )
        assert b["chipset"] == "GRAVITON", (
            f"build {b['buildId']!r} reports chipset {b['chipset']!r}, expected GRAVITON"
        )
        got = mvm.get_microvm_image_build(
            imageIdentifier=image_arn, imageVersion=version, buildId=b["buildId"]
        )
        assert (got["imageArn"], got["imageVersion"], got["chipsetGeneration"]) == (
            b["imageArn"],
            b["imageVersion"],
            b["chipsetGeneration"],
        ), (
            f"GetMicrovmImageBuild for {b['buildId']!r} returned "
            f"{(got['imageArn'], got['imageVersion'], got['chipsetGeneration'])!r} but the list "
            f"summary said {(b['imageArn'], b['imageVersion'], b['chipsetGeneration'])!r}"
        )




def _account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


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


_BUILD_ROLE_POLICY = "sim2real-mvm-build"


def _create_build_role(ctx) -> str:
    """Create the image build role this check owns and return its ARN.

    Lambda assumes the role to read the code artifact; the policy grants S3 reads and log writes.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_build_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::sim2real-*", "arn:aws:s3:::sim2real-*/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY, PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _delete_build_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_image_once_role_is_visible(mvm, budget: float = 90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while the freshly created build role propagates."""
    deadline = time.time() + budget
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ResourceNotFoundException", "ValidationException"):
                raise
            if "role" not in exc.response["Error"].get("Message", "").lower():
                raise
            if time.time() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
