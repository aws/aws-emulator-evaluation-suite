"""container-image-cmd-override."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "container-image-cmd-override"
GROUP = "packaging"
SERVICES = ["lambda"]


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _role_arn(ctx):
    """An execution role this check creates, with the basic CloudWatch Logs policy."""
    iam = ctx.client("iam")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
        )
    )
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while the freshly created role is not yet assumable."""
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


def _unless_gone(call):
    """Teardown: an IAM role or attachment that is already gone is fine; anything else raises."""
    try:
        call()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _cleanup_fn(ctx, lam, name):
    """Run every delete; only an already-absent resource is tolerated, anything else is raised
    naming the step after the others have run."""
    steps = [
        ("DeleteFunctionUrlConfig", lambda: lam.delete_function_url_config(FunctionName=name)),
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
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            failed.append(f"{label}: {exc!r}")
    if failed:
        raise RuntimeError(f"cleanup of {name} failed: {'; '.join(failed)}")


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(
                f"Function {fn} entered Failed: {last.get('StateReason')}"
            )
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA = "application/vnd.docker.image.rootfs.diff.tar.gzip"
#: UploadLayerPart takes parts of at most 10 MiB.
_PART_BYTES = 8 * 1024 * 1024


def _digest(data):
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _layer(entries):
    """A gzip(tar) rootfs layer, byte-reproducible; returns (compressed, uncompressed)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        dirs = set()
        for path, payload, mode in entries:
            # Lambda refuses a layer whose file has no entry for its parent directory.
            parts = path.split("/")[:-1]
            for depth in range(1, len(parts) + 1):
                parent = "/".join(parts[:depth])
                if parent in ("", ".") or parent in dirs:
                    continue
                dirs.add(parent)
                folder = tarfile.TarInfo(name=parent)
                folder.type = tarfile.DIRTYPE
                folder.mode = 0o755
                folder.mtime = 0
                tar.addfile(folder)
            info = tarfile.TarInfo(name=path)
            info.size = len(payload)
            info.mtime = 0
            info.mode = mode
            tar.addfile(info, io.BytesIO(payload))
    tar_bytes = raw.getvalue()
    return gzip.compress(tar_bytes, mtime=0), tar_bytes


def _push_blob(ecr, repo, data):
    """Upload one blob through the ECR API (InitiateLayerUpload / UploadLayerPart parts /
    CompleteLayerUpload); return its digest."""
    digest = _digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    for first in range(0, len(data), _PART_BYTES):
        part = data[first:first + _PART_BYTES]
        ecr.upload_layer_part(
            repositoryName=repo, uploadId=upload_id, partFirstByte=first,
            partLastByte=first + len(part) - 1, layerPartBlob=part,
        )
    ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    return digest


def _put_image(ecr, repo, repo_uri, config, layers):
    """Push the config blob and a schema-2 manifest over already-pushed *layers*
    [(media_type, size, digest)]; return the digest-pinned image URI."""
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_digest = _push_blob(ecr, repo, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": _MANIFEST_V2,
        "config": {"mediaType": _CONFIG_MEDIA, "size": len(config_bytes), "digest": config_digest},
        "layers": [{"mediaType": m, "size": s, "digest": d} for m, s, d in layers],
    }
    digest = ecr.put_image(
        repositoryName=repo, imageManifest=json.dumps(manifest),
        imageManifestMediaType=_MANIFEST_V2,
    )["image"]["imageId"]["imageDigest"]
    return f"{repo_uri}@{digest}"


def _create_repo(ctx, ecr):
    """A private repository this check owns: Lambda takes Code.ImageUri only from a private ECR
    repository in the function's own account and Region."""
    repo = ctx.unique_name("sim2real-behav-img-")
    repo_uri = ecr.create_repository(
        repositoryName=repo, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(lambda: _delete_repo(ecr, repo))
    return repo, repo_uri


def _delete_repo(ecr, repo):
    try:
        ecr.delete_repository(repositoryName=repo, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


def _minimal_image(ecr, repo, repo_uri, marker):
    """A one-layer linux/amd64 image whose layer carries *marker*, so two calls with different
    markers yield two distinct images. Nothing runs it: the checks using it read configuration."""
    gz, tar_bytes = _layer([("workspace/marker.txt", marker.encode(), 0o644)])
    layer_digest = _push_blob(ecr, repo, gz)
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Entrypoint": ["/bin/false"]},
        "rootfs": {"type": "layers", "diff_ids": [_digest(tar_bytes)]},
    }
    return _put_image(ecr, repo, repo_uri, config, [(_LAYER_MEDIA, len(gz), layer_digest)])


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImageConfig can override CMD (the handler path inside the container)."""
    lam = ctx.client("lambda")
    ecr = ctx.client("ecr")
    repo, repo_uri = _create_repo(ctx, ecr)
    image_uri = _minimal_image(ecr, repo, repo_uri, "v1")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=fn_name,
        PackageType="Image",
        Role=_role_arn(ctx),
        Code={"ImageUri": image_uri},
        ImageConfig={"Command": ["index.handler"]},
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda n=fn_name: _cleanup_fn(ctx, lam, n))
    _wait_active(lam, fn_name, timeout_s=120)
    config = lam.get_function_configuration(FunctionName=fn_name)
    img_cfg = config.get("ImageConfigResponse", {}).get("ImageConfig", {})
    assert img_cfg.get("Command") == ["index.handler"], (
        f"Expected ImageConfigResponse.ImageConfig.Command=['index.handler'], got: {img_cfg.get('Command')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
