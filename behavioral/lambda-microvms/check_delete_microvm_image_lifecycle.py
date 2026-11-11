"""delete-microvm-image-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-microvm-image-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda-microvms"]
#: Upper bound for one convergence poll.
POLL_BUDGET_S = 900.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteMicrovmImage on a built image, GetMicrovmImage and a second delete both return
    ResourceNotFoundException (404) and ListMicrovmImages no longer lists the image."""
    client = ctx.client("lambda-microvms")
    image = _provision_ready_image(ctx, ctx.unique_name("del-"))
    image_arn = image["imageArn"]

    got = client.get_microvm_image(imageIdentifier=image_arn)
    assert got["latestActiveImageVersion"] == image["imageVersion"], (
        f"latestActiveImageVersion {got.get('latestActiveImageVersion')!r} != the built version {image['imageVersion']!r}"
    )
    parts = image_arn.split(":")
    assert parts[3] == ctx.region and parts[4] == ctx.account, (
        f"image ARN {image_arn!r} does not carry region {ctx.region!r} and the caller account"
    )

    client.delete_microvm_image(imageIdentifier=image_arn)
    # Gone beat 1: GetMicrovmImage converges to ResourceNotFoundException (404) naming the image.
    _assert_not_found(
        _wait_for_image_gone(ctx, image_arn), "GetMicrovmImage after delete",
        f"MicroVMImage not found for MicroVMImageID: {image_arn}",
    )
    # Gone beat 2: the name-filtered listing no longer contains it.
    listed = [
        i["imageArn"]
        for page in _pages(lambda **kw: client.list_microvm_images(nameFilter=image["name"], **kw))
        for i in page.get("items", [])
    ]
    assert image_arn not in listed, "deleted image still listed by ListMicrovmImages(nameFilter)"
    # Gone beat 3: a second delete on the dead identifier is refused.
    _assert_not_found(
        _client_error(lambda: client.delete_microvm_image(imageIdentifier=image_arn)),
        "DeleteMicrovmImage on the deleted image",
        f"MicroVM image not found: {image_arn}",
    )


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
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.tag_role(RoleName=role_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
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
        raise AssertionError(
            "prerequisite representation-managed-microvm-image-fields-round-trip: "
            "no Lambda-managed MicroVM base images are available in this account/region"
        )
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


def _client_error(fn) -> dict:
    """Call fn(); return its ClientError response. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assert_not_found(resp, what, expected_message):
    """ResourceNotFoundException + HTTP 404 + the exact message."""
    err = resp.get("Error", {})
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == "ResourceNotFoundException", f"{what}: expected ResourceNotFoundException, got {err.get('Code')!r}"
    assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
    assert err.get("Message") == expected_message, (
        f"{what}: expected the message {expected_message!r}, got {err.get('Message')!r}"
    )


def _pages(call):
    """Every page of a nextToken-paginated call."""
    token = None
    while True:
        page = call(**({"nextToken": token} if token else {}))
        yield page
        token = page.get("nextToken")
        if not token:
            return


def _wait_for_image_gone(ctx, image_arn: str, timeout_s: float = POLL_BUDGET_S, interval_s: float = 5.0) -> dict:
    """Poll GetMicrovmImage until it refuses the image; return that ClientError response."""
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = client.get_microvm_image(imageIdentifier=image_arn)["state"]
        except ClientError as exc:
            return exc.response
        time.sleep(interval_s)
    raise AssertionError(f"image {image_arn} was still readable (state={last!r}) after {timeout_s}s of deletion")


def _wait_for_image_state(ctx, image_arn, target_states, timeout_s=POLL_BUDGET_S, interval_s=5.0):
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


def _wait_for_version_state(ctx, image_arn, version, target_states, timeout_s=POLL_BUDGET_S, interval_s=5.0):
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
        client, name=name, base_arn=base_arn, role_arn=role_arn, code_uri=code_uri,
        tags={"sim2real": CHECK}, **create_kwargs
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
    assert ver["status"] == "ACTIVE", f"a freshly successful version must auto-activate, got status {ver.get('status')!r}"
    return image


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
