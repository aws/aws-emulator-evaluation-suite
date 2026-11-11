"""image-function-runs-or-refuses-honestly."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-function-runs-or-refuses-honestly"
GROUP = "packaging"
SERVICES = ["lambda"]

_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA = "application/vnd.docker.image.rootfs.diff.tar.gzip"


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction refuses an Image function whose ImageUri names no image with one exact code
    and message and leaves no function behind, while the same request naming a pushed image
    creates a function that reaches Active.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html
    """
    lam = ctx.client("lambda", config=Config(read_timeout=60, retries={"mode": "standard", "max_attempts": 5}))
    iam = ctx.client("iam")
    ecr = ctx.client("ecr")
    logs = ctx.client("logs")
    role_arn = _execution_role(ctx, iam)
    partition = role_arn.split(":")[1]
    repo, repo_uri = _create_repo(ctx, ecr)
    good_uri = _minimal_image(ecr, repo, repo_uri, "v1")

    good_fn = ctx.unique_name("sim2real-behav-img-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{good_fn}"))
    _create_function(
        lam, FunctionName=good_fn, PackageType="Image", Code={"ImageUri": good_uri},
        Role=role_arn, Timeout=30, MemorySize=256, Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=good_fn),
                             "ResourceNotFoundException"))
    state = _wait_settled(lam, good_fn)
    assert state.get("State") == "Active", (
        f"positive control: a function naming the pushed image {good_uri} settled as "
        f"{state.get('State')!r} ({state.get('StateReason')!r}), expected Active"
    )

    image_uri = f"{ctx.account}.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-behav-img-none:latest"
    fn = ctx.unique_name("sim2real-behav-img-")
    want_message = f"Source image {image_uri} does not exist. Provide a valid source image."
    fn_gone = (
        "ResourceNotFoundException",
        f"Function not found: arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{fn}",
    )
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    try:
        _create_function(
            lam,
            FunctionName=fn,
            PackageType="Image",
            Code={"ImageUri": image_uri},
            Role=role_arn,
            Timeout=30,
            MemorySize=256,
            Tags={"sim2real": CHECK},
        )
    except ClientError as e:
        err = e.response.get("Error", {})
        status = e.response["ResponseMetadata"].get("HTTPStatusCode")
        assert err.get("Code") == "InvalidParameterValueException", (
            f"CreateFunction with a non-existent ImageUri raised {err.get('Code')!r}, "
            "expected 'InvalidParameterValueException'"
        )
        assert status == 400, f"the refusal was HTTP {status!r}, expected 400"
        assert err.get("Message") == want_message, (
            f"CreateFunction's refusal message was {err.get('Message')!r}, expected {want_message!r}"
        )
    else:
        raise AssertionError(
            "CreateFunction with an ImageUri naming no image succeeded; it must be refused, "
            "since there is no image for the function to ever run"
        )

    code, msg, status = _get_function_error(lam, fn)
    assert (code, msg) == fn_gone and status == 404, (
        f"after the refused CreateFunction, GetFunction answered {code!r} HTTP {status!r}: {msg!r}; "
        f"a refused create must not leave a function behind, expected {fn_gone}"
    )


def _execution_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, name))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _get_function_error(lam, fn):
    try:
        lam.get_function(FunctionName=fn)
        return None, None, 200
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message"), e.response["ResponseMetadata"].get("HTTPStatusCode")


def _wait_settled(lam, fn, timeout_s=120.0) -> dict:
    """The configuration once State leaves Pending (Active or Failed)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("State") in ("Active", "Failed", "Inactive"):
            return last
        time.sleep(2)
    raise AssertionError(f"function {fn} stayed Pending for {timeout_s}s: {last!r}")


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


def _minimal_image(ecr, repo, repo_uri, tag):
    """A one-layer linux/amd64 image, pushed under *tag*. Nothing invokes it."""
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
    ecr.put_image(
        repositoryName=repo, imageManifest=json.dumps(manifest), imageManifestMediaType=_MANIFEST_V2,
        imageTag=tag,
    )
    return f"{repo_uri}:{tag}"


def _create_repo(ctx, ecr):
    repo = ctx.unique_name("sim2real-behav-img-")
    repo_uri = ecr.create_repository(
        repositoryName=repo, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(_teardown(lambda: ecr.delete_repository(repositoryName=repo, force=True),
                             "RepositoryNotFoundException"))
    return repo, repo_uri


def _delete_role_if_exists(iam, name) -> None:
    try:
        iam.delete_role(RoleName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
