"""image-runtime-honors-entrypoint-cmd-workdir-and-merges-env."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-runtime-honors-entrypoint-cmd-workdir-and-merges-env"
GROUP = "packaging"
SERVICES = ["lambda"]

_BASIC_EXEC_POLICY = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _partition(ctx) -> str:
    """The session's partition, so an ARN names the partition the check runs in."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]

_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA = "application/vnd.docker.image.rootfs.diff.tar.gzip"

# A Lambda Runtime API client with no library beyond the kernel: a static musl ELF per
# architecture, built once at authoring time (gcc -static against musl-dev) and embedded
# here gzip+base64; its SHA-256 is asserted before use. On every invocation it answers
# with its own argv, cwd and uname machine, plus a fixed set of named env vars, so a
# check can grade what the container actually started with rather than trust the image.
_BOOTSTRAP_AMD64_GZ_B64 = (
    "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"
)
_BOOTSTRAP_AMD64_SHA256 = "628843dbb829c0961bb5dddd7ebe200dd17d7872c7cb31cce69a3b709b9c6db0"

def _bootstrap_bytes() -> bytes:
    gz = base64.b64decode(_BOOTSTRAP_AMD64_GZ_B64)
    raw = gzip.decompress(gz)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _BOOTSTRAP_AMD64_SHA256, (
        f"embedded x86_64 binary hashed to {got!r}, expected {_BOOTSTRAP_AMD64_SHA256!r}"
    )
    return raw


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _layer(entries):
    """A gzip(tar) rootfs layer; entries is [(path, payload, mode)], parent dirs auto-added."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        dirs = set()
        for path, payload, mode in entries:
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


def _push_blob(ecr, repo: str, data: bytes) -> str:
    """Upload one blob through InitiateLayerUpload/UploadLayerPart/CompleteLayerUpload; a
    blob already in the repository (an unchanged layer pushed again) is left as is."""
    digest = _digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo, uploadId=upload_id, partFirstByte=0,
        partLastByte=len(data) - 1, layerPartBlob=data,
    )
    try:
        ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LayerAlreadyExistsException":
            raise
    return digest


def _put_image(ecr, repo: str, repo_uri: str, config: dict, layers, tag: str):
    """Push the config blob and a schema-2 manifest over already-pushed *layers*
    [(media_type, size, digest)], tagged *tag*; return (digest, tagged_uri)."""
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
        imageManifestMediaType=_MANIFEST_V2, imageTag=tag,
    )["image"]["imageId"]["imageDigest"]
    return digest, f"{repo_uri}:{tag}"


def _create_repo(ctx, ecr):
    repo = ctx.unique_name("sim2real-behav-img-")
    repo_uri = ecr.create_repository(
        repositoryName=repo, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(lambda: _delete_repo(ecr, repo))
    return repo, repo_uri


def _delete_repo(ecr, repo: str) -> None:
    try:
        ecr.delete_repository(repositoryName=repo, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return arn


def _unless_gone(call) -> None:
    try:
        call()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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


def _wait_active(lam, fn: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"function {fn} entered Failed: {last.get('StateReason')!r}")
        if last["State"] == "Active":
            return last
        time.sleep(2.0)
    raise AssertionError(f"{fn} did not reach Active within {timeout_s}s; last={last!r}")


def _invoke_json(lam, fn: str, payload: dict) -> dict:
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode())
    body = resp["Payload"].read()
    assert not resp.get("FunctionError"), (
        f"invoke of {fn} returned FunctionError={resp.get('FunctionError')!r}: {body[:500]!r}"
    )
    assert body, f"invoke of {fn} returned an empty payload"
    return json.loads(body)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 150.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; a delayed
    flush after DeleteFunction can recreate it, so one delete is not the teardown."""
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
                raise AssertionError(f"log group {name} still present after {budget_s}s; {absent} clean reads")
            time.sleep(interval_s)


def _delete_function(lam, fn: str) -> None:
    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags(
    "axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A container image's own ENTRYPOINT, CMD, WORKDIR and ENV reach the running process
    untouched, a function Environment variable is added alongside the image's own ENV, and
    GetFunction reports no ImageConfig the function never set.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/images-create.html#images-parms
    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html
    """
    lam = ctx.client("lambda", config=Config(read_timeout=120, retries={"mode": "standard", "max_attempts": 5}))
    ecr = ctx.client("ecr")
    logs = ctx.client("logs")
    repo, repo_uri = _create_repo(ctx, ecr)

    binary = _bootstrap_bytes()
    gz, tar_bytes = _layer([
        ("./var/task/bootstrap", binary, 0o755),
        ("./opt/probe-wd/.keep", b"", 0o644),
    ])
    layer_digest = _push_blob(ecr, repo, gz)
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Entrypoint": ["/var/task/bootstrap"],
            "Cmd": ["from-image-cmd-arg"],
            "WorkingDir": "/opt/probe-wd",
            "Env": ["SIM2REAL_IMG_ONLY=image-only-value", "SIM2REAL_SHARED=from-image"],
        },
        "rootfs": {"type": "layers", "diff_ids": [_digest(tar_bytes)]},
    }
    digest, tagged_uri = _put_image(
        ecr, repo, repo_uri, config, [(_LAYER_MEDIA, len(gz), layer_digest)], tag="v1"
    )

    fn = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    role_arn = _role_arn(ctx)
    _create_function(
        lam,
        FunctionName=fn,
        PackageType="Image",
        Code={"ImageUri": tagged_uri},
        Role=role_arn,
        Timeout=30,
        MemorySize=256,
        Environment={"Variables": {"SIM2REAL_FN_ONLY": "fn-only-value"}},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_function(lam, fn))
    _wait_active(lam, fn)

    got = lam.get_function(FunctionName=fn)
    resolved = got["Code"]["ResolvedImageUri"]
    assert resolved == f"{repo_uri}@{digest}", (
        f"ResolvedImageUri was {resolved!r}, expected the pushed digest {repo_uri}@{digest}"
    )
    assert got["Code"]["ImageUri"] == tagged_uri, (
        f"Code.ImageUri was {got['Code']['ImageUri']!r}, expected the tagged reference {tagged_uri!r}"
    )
    echoed = got["Configuration"].get("ImageConfigResponse")
    assert echoed is None, (
        "GetFunction must not report the image's own ENTRYPOINT/CMD/WORKDIR as an ImageConfig "
        f"when the function set no ImageConfig; got {echoed!r}"
    )

    out = _invoke_json(lam, fn, {"probe": CHECK})
    assert out["argv"] == ["/var/task/bootstrap", "from-image-cmd-arg"], (
        f"argv was {out['argv']!r}, expected the image's own ENTRYPOINT+CMD"
    )
    assert out["cwd"] == "/opt/probe-wd", f"cwd was {out['cwd']!r}, expected the image's own WORKDIR"
    env = out["env"]
    assert env.get("SIM2REAL_IMG_ONLY") == "image-only-value", (
        f"env SIM2REAL_IMG_ONLY was {env.get('SIM2REAL_IMG_ONLY')!r}, expected the image's own ENV"
    )
    assert env.get("SIM2REAL_FN_ONLY") == "fn-only-value", (
        f"env SIM2REAL_FN_ONLY was {env.get('SIM2REAL_FN_ONLY')!r}; the function's Environment "
        "variables must reach the container alongside the image's own ENV"
    )
    assert env.get("SIM2REAL_SHARED") == "from-image", (
        f"env SIM2REAL_SHARED was {env.get('SIM2REAL_SHARED')!r}, expected the image's own ENV "
        "unchanged since the function declared no override for this key"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
