"""container-image-packagetype-immutable-on-update-rejected."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "container-image-packagetype-immutable-on-update-rejected"
GROUP = "packaging"
SERVICES = ["lambda"]


_BASIC_EXEC_POLICY = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _partition(ctx) -> str:
    """The session's partition, so an ARN names the partition the check runs in."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _role_arn(ctx):
    """An execution role this check creates, with the basic CloudWatch Logs policy."""
    iam = ctx.client("iam")
    policy_arn = _BASIC_EXEC_POLICY.format(partition=_partition(ctx))
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    )
    return arn


def _unless_gone(call):
    try:
        call()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _digest(data):
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _push_blob(ecr, repo, data):
    digest = _digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo, uploadId=upload_id, partFirstByte=0,
        partLastByte=len(data) - 1, layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    return digest


def _minimal_image(ecr, repo, repo_uri, marker="v1"):
    """A one-layer linux/amd64 image whose layer carries *marker*. Nothing invokes it: this check
    reads configuration, and two different markers yield two distinct images."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        body = f"sim2real-{marker}\n".encode()
        info = tarfile.TarInfo("marker.txt")
        info.size = len(body)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(body))
    tar_bytes = raw.getvalue()
    gz = gzip.compress(tar_bytes, mtime=0)
    layer_digest = _push_blob(ecr, repo, gz)
    config = {
        "architecture": "amd64", "os": "linux",
        "config": {"Entrypoint": ["/bin/false"]},
        "rootfs": {"type": "layers", "diff_ids": [_digest(tar_bytes)]},
    }
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_digest = _push_blob(ecr, repo, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": _MANIFEST_V2,
        "config": {"mediaType": _CONFIG_MEDIA, "size": len(config_bytes), "digest": config_digest},
        "layers": [{"mediaType": _LAYER_MEDIA, "size": len(gz), "digest": layer_digest}],
    }
    digest = ecr.put_image(
        repositoryName=repo, imageManifest=json.dumps(manifest), imageManifestMediaType=_MANIFEST_V2,
    )["image"]["imageId"]["imageDigest"]
    return f"{repo_uri}@{digest}"


def _create_repo(ctx, ecr):
    repo = ctx.unique_name("sim2real-behav-img-")
    repo_uri = ecr.create_repository(
        repositoryName=repo, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(lambda: _unless_repo_gone(lambda: ecr.delete_repository(repositoryName=repo, force=True)))
    return repo, repo_uri


def _unless_repo_gone(call):
    try:
        call()
    except ClientError as e:
        if e.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _zip_bytes(body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", body)
    return buf.getvalue()


def _create_function(lam, **kwargs):
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    steps = [
        ("DeleteFunction", lambda: lam.delete_function(FunctionName=name)),
        ("DeleteLogGroup",
         lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")),
    ]
    failed = []
    for label, step in steps:
        try:
            step()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                failed.append(f"{label}: {exc}")
    if failed:
        raise RuntimeError(f"cleanup of {name} failed: {'; '.join(failed)}")


def _wait_active(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _wait_update_successful(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"Function {fn} update Failed: {last.get('LastUpdateStatusReason')}")
        if status == "Successful":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} LastUpdateStatus not Successful within {timeout_s}s. Last: {last!r}")


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("expected the call to be refused, but it succeeded")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionCode refuses to switch a function's deployment package type in either
    direction; a same-type update still succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/images-create.html
    """
    lam = ctx.client("lambda")
    ecr = ctx.client("ecr")
    role_arn = _role_arn(ctx)
    repo, repo_uri = _create_repo(ctx, ecr)
    image_uri = _minimal_image(ecr, repo, repo_uri)
    zip_code = _zip_bytes("def handler(event, context):\n    return event\n")

    zip_fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam, FunctionName=zip_fn, PackageType="Zip", Role=role_arn,
                      Code={"ZipFile": zip_code}, Runtime="python3.13", Handler="index.handler", Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda n=zip_fn: _cleanup_fn(ctx, lam, n))
    _wait_active(lam, zip_fn)

    img_fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam, FunctionName=img_fn, PackageType="Image", Role=role_arn, Code={"ImageUri": image_uri},
                     Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda n=img_fn: _cleanup_fn(ctx, lam, n))
    _wait_active(lam, img_fn)

    err = _error(lambda: lam.update_function_code(FunctionName=zip_fn, ImageUri=image_uri))
    assert err.get("Code") == "InvalidParameterValueException", (
        f"zip->image: expected InvalidParameterValueException, got {err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == "Please don't provide ImageUri when updating a function with packageType Zip.", (
        f"zip->image: unexpected message {err.get('Message')!r}"
    )
    after = lam.get_function_configuration(FunctionName=zip_fn)
    assert after["PackageType"] == "Zip", f"zip function's PackageType changed to {after['PackageType']!r}"

    err = _error(lambda: lam.update_function_code(FunctionName=img_fn, ZipFile=zip_code))
    assert err.get("Code") == "InvalidParameterValueException", (
        f"image->zip: expected InvalidParameterValueException, got {err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == "Please provide ImageUri when updating a function with packageType Image.", (
        f"image->zip: unexpected message {err.get('Message')!r}"
    )
    after = lam.get_function_configuration(FunctionName=img_fn)
    assert after["PackageType"] == "Image", f"image function's PackageType changed to {after['PackageType']!r}"

    # Positive control: a same-type update still works for both package types.
    new_zip_code = _zip_bytes("def handler(event, context):\n    return {'v': 2, **event}\n")
    expected_zip_sha256 = base64.b64encode(hashlib.sha256(new_zip_code).digest()).decode()
    resp = lam.update_function_code(FunctionName=zip_fn, ZipFile=new_zip_code)
    assert resp.get("CodeSha256") == expected_zip_sha256, (
        f"zip same-type update: expected CodeSha256 {expected_zip_sha256!r}, got {resp.get('CodeSha256')!r}"
    )
    _wait_update_successful(lam, zip_fn)

    new_image_uri = _minimal_image(ecr, repo, repo_uri, marker="v2")
    expected_image_sha256 = new_image_uri.rsplit("@sha256:", 1)[1]
    resp = lam.update_function_code(FunctionName=img_fn, ImageUri=new_image_uri)
    assert resp.get("CodeSha256") == expected_image_sha256, (
        f"image same-type update: expected CodeSha256 {expected_image_sha256!r}, got {resp.get('CodeSha256')!r}"
    )
    _wait_update_successful(lam, img_fn)
    code = lam.get_function(FunctionName=img_fn)["Code"]
    assert code.get("ImageUri") == new_image_uri, (
        f"image same-type update: expected Code.ImageUri {new_image_uri!r}, got {code.get('ImageUri')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
