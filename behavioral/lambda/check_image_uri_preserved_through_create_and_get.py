"""image-uri-preserved-through-create-and-get."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from behavioral_harness import tags


CHECK = "image-uri-preserved-through-create-and-get"
GROUP = "packaging"
SERVICES = ["lambda"]


def _upload_blob(ecr, repo_name, blob_bytes):
    digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
    avail = ecr.batch_check_layer_availability(repositoryName=repo_name, layerDigests=[digest])
    if avail["layers"] and avail["layers"][0]["layerAvailability"] == "AVAILABLE":
        return digest, avail["layers"][0]["layerSize"]
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name, uploadId=upload_id, partFirstByte=0,
        partLastByte=len(blob_bytes) - 1, layerPartBlob=blob_bytes,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest, len(blob_bytes)


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal image via the raw ECR layer-upload API: an empty gzipped-tar layer and a
    config declaring Entrypoint/Cmd, tied together by a PutImage v2 manifest."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    gz_bytes = gz_buf.getvalue()
    layer_digest, layer_size = _upload_blob(ecr, repo_name, gz_bytes)
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Entrypoint": ["/bootstrap"], "Cmd": ["app.handler"], "WorkingDir": "/var/task"},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size, "digest": config_digest,
        },
        "layers": [{
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": layer_size, "digest": layer_digest,
        }],
    }
    ecr.put_image(repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag)


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _create_role(ctx):
    """An execution role this check creates (Lambda trust + basic logging), removed at cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real:managed", "Value": "true"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only the fresh-role refusal ("cannot be assumed") for at most 90 s."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3.0)  # a role created seconds ago is not yet assumable by Lambda
                continue
            raise


def _wait_settled(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] in ("Active", "Failed"):
            return last
        time.sleep(2.0)
    raise AssertionError(f"{fn} did not settle within {timeout_s}s. Last: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Image function stores Code.ImageUri exactly as supplied: CreateFunction echoes it (if at all)
    and two later GetFunction calls after it settles report the same string plus a digest-pinned
    ResolvedImageUri in the same repository.
    """
    ecr = ctx.client("ecr")
    lam = ctx.client("lambda")

    repo_name = ctx.unique_name("sim2real-behav-imguri-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_minimal_image(ecr, repo_name, "v1")

    image_uri = f"{repo['repositoryUri']}:v1"
    fn_name = ctx.unique_name("sim2real-behav-imguri-fn-")
    created = _create_function(lam,
        FunctionName=fn_name, PackageType="Image", Role=_create_role(ctx),
        Code={"ImageUri": image_uri},
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    created_uri = created.get("Code", {}).get("ImageUri")
    assert created_uri in (None, image_uri), (
        f"CreateFunction response's Code.ImageUri, when present, must equal the supplied "
        f"{image_uri!r}; got {created_uri!r}"
    )

    settled = _wait_settled(lam, fn_name)
    assert settled["State"] == "Active", (
        f"image function failed to activate (this would also invalidate the test): "
        f"{settled.get('StateReason')!r}"
    )

    got = lam.get_function(FunctionName=fn_name)
    got_uri = got["Code"]["ImageUri"]
    assert got_uri == image_uri, (
        f"independent GetFunction read after settling: expected Code.ImageUri == {image_uri!r}, "
        f"got {got_uri!r} -- the control plane must store the exact value, not rewrite it"
    )
    resolved = got["Code"].get("ResolvedImageUri", "")
    expected_repo_prefix = image_uri.rsplit(":", 1)[0]
    assert resolved.startswith(f"{expected_repo_prefix}@sha256:"), (
        f"ResolvedImageUri should pin the SAME repository ({expected_repo_prefix!r}) to a "
        f"digest, got {resolved!r}"
    )

    # A second read rules out a one-shot timing fluke.
    got2 = lam.get_function(FunctionName=fn_name)
    assert got2["Code"]["ImageUri"] == image_uri, (
        f"a second independent GetFunction read returned a different ImageUri: "
        f"{got2['Code']['ImageUri']!r} != {image_uri!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
