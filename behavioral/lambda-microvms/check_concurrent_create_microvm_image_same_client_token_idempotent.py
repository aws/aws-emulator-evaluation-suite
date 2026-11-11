"""concurrent-create-microvm-image-same-client-token-idempotent."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-microvm-image-same-client-token-idempotent"
GROUP = "concurrency"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateMicrovmImage calls sharing the same clientToken and identical
    parameters are idempotent: every racer observes the same imageArn/imageVersion, and
    only one image version is actually created (no duplicate builds race through).
    """
    client = ctx.client("lambda-microvms")
    marker = ctx.unique_name("idem-")
    code_uri = _create_code_artifact(ctx, marker)
    bucket = code_uri.split("//", 1)[1].split("/", 1)[0]
    role_arn = _create_build_role(ctx, bucket)
    base_arn = _pick_base_image_arn(ctx)
    name = ctx.unique_name("sim2real-mvm-idem-").replace("_", "-")[:64]
    client_token = ctx.unique_name("token-")

    def _racer(_: int):
        return _create_image_with_retry(
            client,
            name=name,
            base_arn=base_arn,
            role_arn=role_arn,
            code_uri=code_uri,
            clientToken=client_token,
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_racer, i) for i in range(5)]
    responses = [f.result() for f in futures if f.exception() is None]
    image_arns = {r["imageArn"] for r in responses}
    for created_arn in image_arns:
        ctx.on_cleanup(lambda created_arn=created_arn: _delete_image_when_ready(ctx, created_arn))
    failures = [f.exception() for f in futures if f.exception() is not None]
    assert not failures, f"every same-token racer must succeed, {len(failures)} raised: {failures!r}"

    versions = {r["imageVersion"] for r in responses}
    assert len(image_arns) == 1, f"idempotent create must return exactly one imageArn, got {image_arns}"
    assert len(versions) == 1, f"idempotent create must return exactly one imageVersion, got {versions}"

    image_arn = image_arns.pop()
    client.tag_resource(Resource=image_arn, Tags={"sim2real:managed": "true"})

    versions_listed = client.list_microvm_image_versions(imageIdentifier=image_arn)["items"]
    assert len(versions_listed) == 1, (
        f"exactly one version should exist after idempotent concurrent creates, got {len(versions_listed)}"
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
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
