"""arm64-image-function-runtime-reports-aarch64."""
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

CHECK = "arm64-image-function-runtime-reports-aarch64"
GROUP = "packaging"
SERVICES = ["lambda"]

_BASIC_EXEC_POLICY = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _partition(ctx) -> str:
    """The session's partition, so an ARN names the partition the check runs in."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]

_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA = "application/vnd.docker.image.rootfs.diff.tar.gzip"

# A Lambda Runtime API client with no library beyond the kernel: a static musl ELF for the
# aarch64 target, built once at authoring time (gcc -static against musl-dev) and embedded
# here gzip+base64; its SHA-256 is asserted before use. On every invocation it answers
# with its own argv, cwd and uname machine, plus a fixed set of named env vars, so a
# check can grade what the container actually started with rather than trust the image.
_BOOTSTRAP_ARM64_GZ_B64 = (
    "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"
    "8RlDtbRPfFZgeAt93a3/AKBOj1L8GPMm1ssUEJ/TiLZAIwi370H7jj8qCvGAlRq99GaaT9ofWM1/H7QJVNci82JF6x7j7gDQRlz0x5a098WsYB5gDRF3"
    "6z/+SyOPlVv1eXoA55W/KsqzKh55Gh73ahMlch/EltM6FcUg9PN2/m5xWbDKXKuaE7FMzEe/MZ8oyh9pUL8HfP3uGzCAg/lS9D+N/huHJAFP8XyfKkru"
    "gHrG8wXU70D9g4zHxkFoqvJziuF9pijryV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8"
    "xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8xV/8"
    "xV/8xV/8xV/8xV/8xV/8xV/8xV/+/1amBcrqtydA+w5/TPueqH/L+veOGenq99P69z8rS6cN7jdNsWrz6PVbBPkbx+UPGTdRH9eo9/ddOzdr12b92lds"
    "0/4Bfmb+R6SF6el3myda16xftS7PPP2uKTOmTM9euap0xrQZydPumjZnkl5n9lUQTSnJLyktLrXn0JR1haV5U1au2zAlZ8OqNbl3rsqlKavWrSqlKaV5"
    "G/HvClzQlOJC/tvRNCUvP3tFsX1tntYn215cbN+k9fH95n5TivPWYAhNWVlYqtXQlJySEpriKFyr/m3w/48K/23UQJUCWnlQp6f6N09J+3usA4thyPXt"
    "+HDXAP3ax78t+vjwfzI+ccj4Xfr4Xfr4K5sG9x8KL2nIeB//nZv/tfmn6eN969+lj9+lj78c9j/PnzJkvPNJff4ntesPxcH9TUPGp+HDf1BW8omjLrdm"
    "5Zv7m4Z8L8Fn+IDxPj2Y+C+Of0jHXxqij9P08RPpf17/yiHjH9THP6iPr/0n868ZMl6jCOm1X59v6HqK9TqpD780/VvQ7ZLwP+L/iD7TtK+tUxs3fUi9"
    "8A3f0jfolVXv4fwH433l/wGtJuDaiAQBAA=="
)
_BOOTSTRAP_ARM64_SHA256 = "12a5a92462f918696d8250361d89035c5b24ade7c141a53e00a3719bba0af3d7"

def _bootstrap_bytes() -> bytes:
    gz = base64.b64decode(_BOOTSTRAP_ARM64_GZ_B64)
    raw = gzip.decompress(gz)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _BOOTSTRAP_ARM64_SHA256, (
        f"embedded aarch64 binary hashed to {got!r}, expected {_BOOTSTRAP_ARM64_SHA256!r}"
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Image function created with Architectures=[arm64] actually runs its arm64 image:
    the process the container starts reports an aarch64 machine, not x86_64.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/images-create.html#images-reqs
    """
    lam = ctx.client("lambda", config=Config(read_timeout=120, retries={"mode": "standard", "max_attempts": 5}))
    ecr = ctx.client("ecr")
    logs = ctx.client("logs")
    repo, repo_uri = _create_repo(ctx, ecr)

    binary = _bootstrap_bytes()
    gz, tar_bytes = _layer([("./var/task/bootstrap", binary, 0o755)])
    layer_digest = _push_blob(ecr, repo, gz)
    config = {
        "architecture": "arm64",
        "os": "linux",
        "config": {"Entrypoint": ["/var/task/bootstrap"], "WorkingDir": "/var/task"},
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
        Architectures=["arm64"],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_function(lam, fn))
    cfg = _wait_active(lam, fn)
    assert cfg["Architectures"] == ["arm64"], (
        f"Architectures was {cfg['Architectures']!r}, expected ['arm64']"
    )
    resolved = lam.get_function(FunctionName=fn)["Code"]["ResolvedImageUri"]
    assert resolved.endswith(f"@{digest}"), (
        f"GetFunction's Code.ResolvedImageUri was {resolved!r}, expected it to end with "
        f"{'@' + digest!r}, the digest PutImage returned for the pushed manifest"
    )

    out = _invoke_json(lam, fn, {"probe": CHECK})
    assert out["arch"] == "aarch64", (
        f"the running process reported uname machine {out['arch']!r}; an arm64 Architectures "
        "function must actually run the arm64 image, not an x86_64 one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
