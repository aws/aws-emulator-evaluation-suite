"""delete-microvm-image-version-with-multiple-versions."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-microvm-image-version-with-multiple-versions"
GROUP = "image-version-lifecycle"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMicrovmImageVersion removes a non-last version: it disappears from reads and lists,
    a later UpdateMicrovmImageVersion gets ResourceNotFoundException, and the other version
    and the image itself are untouched."""
    client = ctx.client("lambda-microvms")
    image = _provision_ready_image(ctx, ctx.unique_name("verdel-"))
    image_arn = image["imageArn"]
    old_version = image["imageVersion"]

    updated = client.update_microvm_image(
        imageIdentifier=image_arn,
        baseImageArn=image["baseImageArn"],
        buildRoleArn=image["roleArn"],
        codeArtifact={"uri": image["codeUri"]},
    )
    new_version = updated["imageVersion"]
    assert new_version != old_version, "update must produce a new, distinct version identifier"
    ver = _wait_for_version_state(ctx, image_arn, new_version, {"SUCCESSFUL", "FAILED"})
    assert ver["state"] == "SUCCESSFUL", f"second version build did not succeed: {ver.get('stateReason')}"

    # Both versions are listed, so this is not the last-version case (which is rejected).
    before_ids = {v["imageVersion"] for v in _all_versions(client, image_arn)}
    assert {old_version, new_version}.issubset(before_ids), (
        f"expected both {old_version!r} and {new_version!r} listed before the delete, got {before_ids!r}"
    )

    deleted = client.delete_microvm_image_version(imageIdentifier=image_arn, imageVersion=old_version)
    assert deleted["imageVersion"] == old_version, (
        f"DeleteMicrovmImageVersion echoed version {deleted['imageVersion']!r}, expected {old_version!r}"
    )
    assert deleted["state"] in ("DELETING", "DELETED"), (
        f"deleting the non-last version {old_version!r} answered state {deleted['state']!r}, expected "
        f"DELETING or DELETED -- the last-version case answers ValidationException instead of a state"
    )

    # EFFECT PRESENT, via an independent read: the deleted version becomes unreachable...
    _await_version_gone(client, image_arn, old_version, 240)

    # ...while the surviving version and the image itself are untouched.
    after_ids = {v["imageVersion"] for v in _all_versions(client, image_arn)}
    assert old_version not in after_ids, (
        f"deleted version {old_version!r} is still listed by ListMicrovmImageVersions: {after_ids!r}"
    )
    assert new_version in after_ids, (
        f"surviving version {new_version!r} disappeared from ListMicrovmImageVersions after an "
        f"unrelated version was deleted: {after_ids!r}"
    )
    still_image = client.get_microvm_image(imageIdentifier=image_arn)
    assert still_image["state"] not in ("DELETING", "DELETED", "DELETE_FAILED"), (
        f"deleting version {old_version!r} must not touch the image's own lifecycle, got state "
        f"{still_image['state']!r}"
    )

    # Mutating the deleted version returns ResourceNotFoundException naming image and version.
    error = _client_error(
        lambda: client.update_microvm_image_version(
            imageIdentifier=image_arn, imageVersion=old_version, status="INACTIVE"
        )
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"mutating the deleted version {old_version!r} answered {error!r}, expected "
        f"ResourceNotFoundException"
    )
    assert error.get("Message") == (
        f"MicroVM image version not found: {image_arn}, version: {old_version}"
    ), error


def _app_zip_bytes(marker: str) -> bytes:
    app_js = (
        "const http = require('http');\n"
        "const server = http.createServer((req, res) => {\n"
        "  res.writeHead(200, { 'Content-Type': 'application/json' });\n"
        f"  res.end(JSON.stringify({{ status: 'ok', marker: '{marker}', path: req.url }}));\n"
        "});\n"
        "server.listen(8080, () => { console.log('listening'); });\n"
    )
    dockerfile = (
        "FROM node:24-alpine\n"
        "WORKDIR /app\n"
        "COPY app.js .\n"
        "EXPOSE 8080\n"
        'CMD ["node", "app.js"]\n'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.js", app_js)
        zf.writestr("Dockerfile", dockerfile)
    return buf.getvalue()


def _create_code_artifact(ctx, marker: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mvm-").lower().replace("_", "-")[:63]
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="app.zip", Body=_app_zip_bytes(marker))
    return f"s3://{bucket}/app.zip"


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_build_role(ctx, bucket: str) -> str:
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="mvm-build-policy", PolicyDocument=json.dumps(policy))
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="mvm-build-policy")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _pick_base_image_arn(ctx) -> str:
    client = ctx.client("lambda-microvms")
    items = client.list_managed_microvm_images().get("items", [])
    if not items:
        raise AssertionError("no Lambda-managed MicroVM base images are available in this account/region")
    return items[0]["imageArn"]


def _create_image_with_retry(client, *, name, base_arn, role_arn, code_uri, timeout_s=90.0, interval_s=3.0, **extra):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return client.create_microvm_image(
                name=name,
                baseImageArn=base_arn,
                buildRoleArn=role_arn,
                codeArtifact={"uri": code_uri},
                **extra,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_image_when_ready(ctx, image_arn: str) -> None:
    """Teardown: wait (bounded) for the image to settle, then delete it. A gone image is done."""
    client = ctx.client("lambda-microvms")
    settled = {"CREATED", "CREATE_FAILED", "UPDATED", "UPDATE_FAILED"}
    deadline = time.monotonic() + 900.0
    while time.monotonic() < deadline:
        try:
            state = client.get_microvm_image(imageIdentifier=image_arn)["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if state in settled:
            break
        time.sleep(5.0)
    try:
        client.delete_microvm_image(imageIdentifier=image_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_image_state(ctx, image_arn, target_states, timeout_s=900.0, interval_s=5.0):
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_microvm_image(imageIdentifier=image_arn)
        last = resp["state"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"image {image_arn} never reached {target_states}, last state={last}")


def _wait_for_version_state(ctx, image_arn, version, target_states, timeout_s=900.0, interval_s=5.0):
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
        last = resp["state"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"version {version} of {image_arn} never reached {target_states}, last state={last}")


def _create_image(ctx, marker: str, **create_kwargs) -> dict:
    client = ctx.client("lambda-microvms")
    code_uri = _create_code_artifact(ctx, marker)
    bucket = code_uri.split("//", 1)[1].split("/", 1)[0]
    role_arn = _create_build_role(ctx, bucket)
    base_arn = _pick_base_image_arn(ctx)
    name = ctx.unique_name("sim2real-mvm-img-").replace("_", "-")[:64]
    resp = _create_image_with_retry(
        client,
        name=name,
        base_arn=base_arn,
        role_arn=role_arn,
        code_uri=code_uri,
        tags={"sim2real-check": CHECK},
        **create_kwargs,
    )
    image_arn = resp["imageArn"]
    ctx.on_cleanup(lambda: _delete_image_when_ready(ctx, image_arn))
    return {
        "imageArn": image_arn,
        "imageVersion": resp["imageVersion"],
        "roleArn": role_arn,
        "codeUri": code_uri,
        "baseImageArn": base_arn,
        "name": name,
    }


def _provision_ready_image(ctx, marker: str) -> dict:
    image = _create_image(ctx, marker)
    img = _wait_for_image_state(ctx, image["imageArn"], {"CREATED", "CREATE_FAILED"})
    assert img["state"] == "CREATED", f"prerequisite image build failed: {img.get('stateReason')}"
    ver = _wait_for_version_state(ctx, image["imageArn"], image["imageVersion"], {"SUCCESSFUL", "FAILED"})
    assert ver["state"] == "SUCCESSFUL", f"prerequisite version build failed: {ver.get('stateReason')}"
    return image


def _all_versions(client, image_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = client.list_microvm_image_versions(
            imageIdentifier=image_arn, **({"nextToken": token} if token else {})
        )
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _client_error(fn) -> dict:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


def _await_version_gone(client, image_arn: str, version: str, budget: float) -> None:
    deadline = time.time() + budget
    last = None
    while time.time() < deadline:
        try:
            last = client.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"version {version!r} of {image_arn!r} reached DELETE_FAILED")
        time.sleep(5)
    raise AssertionError(
        f"version {version!r} of {image_arn!r} was still readable ({last!r}) after {budget}s of deletion"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
