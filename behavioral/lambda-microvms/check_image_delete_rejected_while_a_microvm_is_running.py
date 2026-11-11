"""image-delete-rejected-while-a-microvm-is-running."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-delete-rejected-while-a-microvm-is-running"
GROUP = "image-version-lifecycle"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMicrovmImage is refused with ValidationException while a microvm runs off the image,
    leaving image and version untouched, and is accepted once that microvm terminates.
    """
    mvm = ctx.client("lambda-microvms")
    image_arn, version = _build_a_runnable_image(ctx, mvm)

    started = mvm.run_microvm(imageIdentifier=image_arn, maximumDurationInSeconds=600)
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))
    _await_microvm_state(mvm, microvm_id, {"RUNNING"}, 120)

    error = _client_error(lambda: mvm.delete_microvm_image(imageIdentifier=image_arn))
    assert error.get("Code") == "ValidationException", (
        f"deleting an image with a RUNNING microvm answered {error!r}, expected "
        f"ValidationException"
    )
    assert error.get("Message") == "Cannot delete microvm image with running microvms.", error

    # EFFECT ABSENT: the image and its version are untouched by the refused delete.
    image = mvm.get_microvm_image(imageIdentifier=image_arn)
    assert image["state"] == "CREATED", (
        f"the refused delete moved the image to {image['state']!r}, expected CREATED"
    )
    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert (ver["state"], ver["status"]) == ("SUCCESSFUL", "ACTIVE"), (
        f"the refused delete left the version at {(ver['state'], ver['status'])!r}, expected "
        f"('SUCCESSFUL', 'ACTIVE')"
    )

    # POSITIVE CONTROL: the same delete is accepted once nothing runs off the image.
    mvm.terminate_microvm(microvmIdentifier=microvm_id)
    _await_microvm_state(mvm, microvm_id, {"TERMINATED"}, 120)
    deleted = mvm.delete_microvm_image(imageIdentifier=image_arn)
    assert deleted["state"] == "DELETING", (
        f"DeleteMicrovmImage returned {deleted['state']!r} once the microvm was terminated, "
        f"expected DELETING"
    )

    # INDEPENDENT READ: teardown time varies (seconds to over a minute), so accept either
    # point on the async progression rather than a fixed terminal state.
    seen = _read_after_delete(mvm, image_arn)
    assert seen in ("DELETING", "GONE"), (
        f"an independent read right after the accepted delete answered {seen!r}, expected "
        f"DELETING or GONE"
    )


def _own_build_role(ctx, bucket: str) -> str:
    """A build role this check creates and deletes, allowed to read the code artifact in its
    own bucket and to write build logs."""
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
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="mvm-build-policy", PolicyDocument=json.dumps(policy))
    return role_arn


def _delete_own_role(iam, role_name: str) -> None:
    for call in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="mvm-build-policy"),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
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


def _all_microvms(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvms(**kw, **({"nextToken": token} if token else {}))
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


def _read_after_delete(mvm, image_arn: str) -> str:
    try:
        return mvm.get_microvm_image(imageIdentifier=image_arn)["state"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _await_microvm_state(mvm, microvm_id: str, wanted: set[str], budget: float) -> dict:
    deadline = time.time() + budget
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm(microvmIdentifier=microvm_id)
        if seen["state"] in wanted:
            return seen
        time.sleep(2)
    raise AssertionError(
        f"microvm {microvm_id!r} never reached one of {sorted(wanted)!r} within {budget}s; "
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


def _terminate(mvm, microvm_id: str) -> None:
    try:
        mvm.terminate_microvm(microvmIdentifier=microvm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _build_a_runnable_image(ctx, mvm) -> tuple[str, str]:
    """Build a real, runnable MicroVM image and return (imageArn, imageVersion).

    RunMicrovm refuses a managed base image outright, so a customer image must be built first.
    """
    name = ctx.unique_name("sim2real-behav-mvm-")
    s3 = ctx.client("s3")

    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    role = _own_build_role(ctx, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux:2023\n"
            "RUN echo sim2real > /sim2real.txt\n"
            'CMD ["/bin/sh","-c","while true; do sleep 30; done"]\n',
        )
    s3.put_object(Bucket=name, Key="code.zip", Body=buf.getvalue())

    created = _create_image_retrying(
        mvm,
        name=name,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}/code.zip"},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    settled = _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 260)
    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert settled["state"] == "CREATED" and ver["state"] == "SUCCESSFUL", (
        f"the image build did not succeed: image {settled['state']!r}, version "
        f"{ver['state']!r}, reason {ver.get('stateReason')!r}"
    )
    assert ver["status"] == "ACTIVE", (
        f"a successful build left the version {ver['status']!r}, expected ACTIVE"
    )
    return image_arn, version


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    token = None
    while True:
        page = s3.list_objects_v2(
            Bucket=bucket, **({"ContinuationToken": token} if token else {})
        )
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        token = page.get("NextContinuationToken")
        if not token:
            break
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
