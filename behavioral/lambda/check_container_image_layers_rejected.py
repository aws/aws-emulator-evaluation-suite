"""container-image-layers-rejected."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "container-image-layers-rejected"
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


def _minimal_image(ecr, repo, repo_uri):
    """A one-layer linux/amd64 image. Nothing invokes it: this check reads configuration."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        body = b"sim2real\n"
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction rejects a real Layers entry for PackageType=Image; the function is not created.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html
    """
    lam = ctx.client("lambda")
    ecr = ctx.client("ecr")
    role_arn = _role_arn(ctx)
    repo, repo_uri = _create_repo(ctx, ecr)
    image_uri = _minimal_image(ecr, repo, repo_uri)

    layer_zip = io.BytesIO()
    with zipfile.ZipFile(layer_zip, "w") as zf:
        zf.writestr("python/marker.txt", "sim2real")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    layer_arn = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": layer_zip.getvalue()},
    )["LayerVersionArn"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(
        LayerName=layer_name, VersionNumber=int(layer_arn.rsplit(":", 1)[1]),
    ))

    bad_fn = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda n=bad_fn: _cleanup_fn(ctx, lam, n))
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=bad_fn, PackageType="Image", Role=role_arn, Code={"ImageUri": image_uri},
                Layers=[layer_arn], Tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", ""):
                if time.monotonic() < deadline:
                    time.sleep(3)
                    continue
            assert err.get("Code") == "InvalidParameterValueException", (
                f"expected InvalidParameterValueException, got {err.get('Code')!r}: {err.get('Message')!r}"
            )
            assert err.get("Message") == (
                "Lambda layers are not supported for functions created with container images."
            ), f"unexpected message: {err.get('Message')!r}"
            break
        else:
            raise AssertionError("expected CreateFunction to be refused, but it succeeded")

    partition = role_arn.split(":")[1]
    gone = ("ResourceNotFoundException",
            f"Function not found: arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{bad_fn}")
    try:
        lam.get_function(FunctionName=bad_fn)
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err["Code"], err["Message"]) == gone, (
            f"expected the refused function to be absent with {gone!r}, got {err!r}"
        )
    else:
        raise AssertionError(f"refused function {bad_fn} unexpectedly exists")

    # Positive control: the identical image, with no Layers, creates successfully.
    good_fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam, FunctionName=good_fn, PackageType="Image", Role=role_arn, Code={"ImageUri": image_uri},
                     Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda n=good_fn: _cleanup_fn(ctx, lam, n))
    _wait_active(lam, good_fn)
    config = lam.get_function_configuration(FunctionName=good_fn)
    assert config["PackageType"] == "Image", f"positive control: expected PackageType='Image', got {config.get('PackageType')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
