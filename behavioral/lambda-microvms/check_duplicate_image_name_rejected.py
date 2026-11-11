"""duplicate-image-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-image-name-rejected"
GROUP = "image-naming"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateMicrovmImage under an existing name is refused and creates nothing.

    AWS answers ValidationException "A MicroVM image with the name '<name>' already exists in this
    account" (not the modelled ConflictException), leaving exactly ONE image and no new version.
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    role = _create_build_role(ctx)
    name = ctx.unique_name("sim2real-behav-mvm-")

    first = _create_image_once_role_is_visible(mvm,
        name=name, baseImageArn=base, buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-origin": "create"},
    )
    image_arn = first["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))

    code, message = _error(
        lambda: mvm.create_microvm_image(
            name=name, baseImageArn=base, buildRoleArn=role,
            codeArtifact={"uri": f"s3://{name}-absent/code2.zip"},
        )
    )
    assert code == "ValidationException", (
        f"the duplicate-name create answered {code!r}; real AWS answers ValidationException "
        f"(the model declares ConflictException for this operation)"
    )
    expected_message = f"A MicroVM image with the name '{name}' already exists in this account"
    assert message == expected_message, (
        f"the ValidationException message was {message!r}, expected {expected_message!r}"
    )

    # EFFECT ABSENT: one image under that name, still carrying exactly one version.
    same_name = [i for i in _all_customer_images(mvm) if i["name"] == name]
    assert len(same_name) == 1, (
        f"{len(same_name)} images carry the name {name!r} after a refused duplicate: "
        f"{[i['imageArn'] for i in same_name]!r}"
    )
    versions = _all_versions(mvm, image_arn)
    assert len(versions) == 1, (
        f"the refused duplicate left {len(versions)} versions "
        f"{[v['imageVersion'] for v in versions]!r} on {image_arn!r}, expected 1"
    )

    # POSITIVE CONTROL: the same request under a free name is accepted.
    other = ctx.unique_name("sim2real-behav-mvm-")
    ok = mvm.create_microvm_image(
        name=other, baseImageArn=base, buildRoleArn=role,
        codeArtifact={"uri": f"s3://{other}-absent/code.zip"},
        tags={"sim2real-origin": "create"},
    )
    other_arn = ok["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, other_arn))
    assert ok["name"] == other, (
        f"the control create returned name {ok['name']!r}, expected {other!r}"
    )

    # TERMINAL READ: independent of the mutating call above, at the destination.
    listed = [i for i in _all_customer_images(mvm) if i["name"] == other]
    assert len(listed) == 1 and listed[0]["imageArn"] == other_arn, (
        f"ListMicrovmImages shows {len(listed)} image(s) named {other!r} after the control "
        f"create succeeded, expected exactly one matching imageArn {other_arn!r}: {listed!r}"
    )

def _account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
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


_BUILD_ROLE_POLICY = "sim2real-mvm-build"


def _create_build_role(ctx) -> str:
    """Create the image build role this check owns and return its ARN.

    Lambda assumes the role to read the code artifact, so the inline policy grants the S3
    reads on the check's own sim2real- buckets and the build's log writes.
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
