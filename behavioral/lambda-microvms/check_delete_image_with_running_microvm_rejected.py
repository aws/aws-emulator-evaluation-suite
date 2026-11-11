"""delete-image-with-running-microvm-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-image-with-running-microvm-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMicrovmImage is rejected with ValidationException while a MicroVM using it is
    still running; the image survives untouched (effect absent). It succeeds (the
    positive control) once that dependent MicroVM is terminated.
    """
    client = ctx.client("lambda-microvms")
    image = _provision_ready_image(ctx, ctx.unique_name("depd-"))
    started = _run_microvm(ctx, image)
    microvm_id = started["microvmId"]
    _wait_for_microvm_state(ctx, microvm_id, {"RUNNING"})

    code, message = _error(lambda: client.delete_microvm_image(imageIdentifier=image["imageArn"]))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Cannot delete microvm image with running microvms.", message

    # EFFECT ABSENT: the refused delete leaves the image and its version untouched.
    still_there = client.get_microvm_image(imageIdentifier=image["imageArn"])
    assert still_there["state"] == "CREATED", (
        f"the refused delete moved the image to {still_there['state']!r}, expected CREATED"
    )
    ver = client.get_microvm_image_version(
        imageIdentifier=image["imageArn"], imageVersion=image["imageVersion"]
    )
    assert (ver["state"], ver["status"]) == ("SUCCESSFUL", "ACTIVE"), (
        f"the refused delete left the version at {(ver['state'], ver['status'])!r}, "
        "expected ('SUCCESSFUL', 'ACTIVE')"
    )

    # POSITIVE CONTROL: the identical call succeeds once the dependent MicroVM is gone.
    client.terminate_microvm(microvmIdentifier=microvm_id)
    _wait_for_microvm_state(ctx, microvm_id, {"TERMINATED"})
    client.delete_microvm_image(imageIdentifier=image["imageArn"])
    _wait_for_image_gone(ctx, image["imageArn"])


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


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
    # us-east-1 doesn't take LocationConstraint; other regions require it
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    client = ctx.client("lambda-microvms")
    try:
        _wait_for_image_state(
            ctx, image_arn, {"CREATED", "CREATE_FAILED", "UPDATED", "UPDATE_FAILED", "DELETED"}, timeout_s=900.0
        )
    except AssertionError:
        pass
    except ClientError as exc:
        # GetMicrovmImage answers ResourceNotFoundException once the image is already gone.
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    try:
        client.delete_microvm_image(imageIdentifier=image_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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


def _wait_for_image_gone(ctx, image_arn, timeout_s=300.0, interval_s=5.0):
    """A completed delete makes GetMicrovmImage 404 outright -- there is no stable, readable
    DELETED state (an accepted delete goes straight from DELETING to
    ResourceNotFoundException)."""
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = client.get_microvm_image(imageIdentifier=image_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        last = resp["state"]
        assert last != "DELETE_FAILED", f"image delete failed: {resp.get('stateReason')}"
        assert last == "DELETING", f"image {image_arn} in unexpected state {last!r} after an accepted delete"
        time.sleep(interval_s)
    raise AssertionError(f"image {image_arn} was not reported not-found within {timeout_s}s, last state={last}")


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
        client, name=name, base_arn=base_arn, role_arn=role_arn, code_uri=code_uri, **create_kwargs
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


def _network_connector_arn(ctx, name: str) -> str:
    return f"arn:aws:lambda:{ctx.region}:aws:network-connector:aws-network-connector:{name}"


def _terminate_microvm(ctx, microvm_id: str) -> None:
    client = ctx.client("lambda-microvms")
    try:
        client.terminate_microvm(microvmIdentifier=microvm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_microvm_state(ctx, microvm_id, target_states, timeout_s=600.0, interval_s=5.0):
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_microvm(microvmIdentifier=microvm_id)
        last = resp["state"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"microvm {microvm_id} never reached {target_states}, last state={last}")


def _run_microvm(ctx, image: dict, **kwargs) -> dict:
    client = ctx.client("lambda-microvms")
    ingress = kwargs.pop("ingressNetworkConnectors", [_network_connector_arn(ctx, "ALL_INGRESS")])
    egress = kwargs.pop("egressNetworkConnectors", [_network_connector_arn(ctx, "INTERNET_EGRESS")])
    resp = client.run_microvm(
        imageIdentifier=image["imageArn"],
        ingressNetworkConnectors=ingress,
        egressNetworkConnectors=egress,
        **kwargs,
    )
    microvm_id = resp["microvmId"]
    ctx.on_cleanup(lambda: _terminate_microvm(ctx, microvm_id))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
