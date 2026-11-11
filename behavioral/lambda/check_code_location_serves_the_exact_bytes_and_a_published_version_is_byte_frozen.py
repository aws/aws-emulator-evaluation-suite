"""code-location-serves-the-exact-bytes-and-a-published-version-is-byte-frozen."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-location-serves-the-exact-bytes-and-a-published-version-is-byte-frozen"
GROUP = "packaging"
SERVICES = ["lambda"]

# Marks a failure of the target's own data-plane endpoint in an assertion message.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_SOURCE_V1 = 'MARKER = "code-v1"\n\n\ndef handler(event, context):\n    return {"marker": MARKER}\n'
_SOURCE_V2 = 'MARKER = "code-v2"\n\n\ndef handler(event, context):\n    return {"marker": MARKER}\n'


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Code.Location downloads the exact archive whose hash CodeSha256 reports, and a published
    version keeps serving its original bytes after $LATEST is replaced.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_FunctionCodeLocation.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _create_execution_role(ctx, iam)

    zip_v1 = _make_zip({"index.py": _SOURCE_V1})
    zip_v2 = _make_zip({"index.py": _SOURCE_V2})
    assert zip_v1 != zip_v2, "the two deployment packages must differ or the check proves nothing"

    fn = ctx.unique_name("sim2real-behav-codeloc-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_v1},
        MemorySize=128,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    # ---- leg 1: the presigned URL serves an archive whose hash is the one just reported ----
    got = lam.get_function(FunctionName=fn)
    code = got["Code"]
    reported_v1 = got["Configuration"]["CodeSha256"]
    location_v1 = code.get("Location") or ""
    assert location_v1.startswith("https://"), (
        f"GetFunction must report Code.Location as an absolute https presigned URL, got "
        f"{location_v1!r} (Code keys: {sorted(code)})"
    )
    assert code.get("RepositoryType") == "S3", (
        f"a .zip function's code must be hosted on S3, GetFunction reported RepositoryType="
        f"{code.get('RepositoryType')!r}"
    )

    bytes_v1 = _download(ctx, location_v1)
    assert _b64_sha256(bytes_v1) == reported_v1, (
        f"the archive served by Code.Location does not hash to the CodeSha256 reported by the same "
        f"GetFunction call: downloaded {len(bytes_v1)} bytes hashing to {_b64_sha256(bytes_v1)!r}, "
        f"reported {reported_v1!r}"
    )
    # Compared per zip member, not whole archive: the service may repackage a ZipFile upload.
    assert _zip_member(bytes_v1, "index.py") == _SOURCE_V1, (
        "the downloaded archive does not contain the handler source that was uploaded; got "
        f"{_zip_member(bytes_v1, 'index.py')!r}"
    )

    # ---- leg 2: publish, then move $LATEST to different bytes ----
    published = lam.publish_version(FunctionName=fn)
    version = published["Version"]
    assert version != "$LATEST", f"PublishVersion must mint a numbered version, got {version!r}"
    assert published["CodeSha256"] == reported_v1, (
        f"the published version must carry the code that was current when it was published: "
        f"expected {reported_v1!r}, PublishVersion reported {published['CodeSha256']!r}"
    )

    lam.update_function_code(FunctionName=fn, ZipFile=zip_v2)
    _wait_last_update_successful(lam, fn)

    latest = lam.get_function(FunctionName=fn)
    reported_v2 = latest["Configuration"]["CodeSha256"]
    assert reported_v2 != reported_v1, (
        f"UpdateFunctionCode with different bytes must change CodeSha256, it stayed {reported_v2!r}"
    )

    bytes_latest = _download(ctx, latest["Code"]["Location"])
    assert _b64_sha256(bytes_latest) == reported_v2, (
        f"$LATEST's Code.Location serves an archive hashing to {_b64_sha256(bytes_latest)!r} but "
        f"GetFunction reports CodeSha256 {reported_v2!r}"
    )
    assert _zip_member(bytes_latest, "index.py") == _SOURCE_V2, (
        "after UpdateFunctionCode, $LATEST's presigned URL still serves the OLD handler source; got "
        f"{_zip_member(bytes_latest, 'index.py')!r}"
    )

    # ---- leg 3: the published version's BYTES are frozen, not just its hash string ----
    pinned = lam.get_function(FunctionName=fn, Qualifier=version)
    pinned_sha = pinned["Configuration"]["CodeSha256"]
    assert pinned_sha == reported_v1, (
        f"version {version} must still report the code it was published with: expected "
        f"{reported_v1!r}, got {pinned_sha!r}"
    )
    bytes_pinned = _download(ctx, pinned["Code"]["Location"])
    assert _b64_sha256(bytes_pinned) == reported_v1, (
        f"version {version}'s presigned URL serves an archive hashing to "
        f"{_b64_sha256(bytes_pinned)!r}; the version was published at {reported_v1!r}, so the "
        f"published bytes were not frozen"
    )
    assert _zip_member(bytes_pinned, "index.py") == _SOURCE_V1, (
        f"version {version} must keep serving the v1 handler source after $LATEST moved on; got "
        f"{_zip_member(bytes_pinned, 'index.py')!r}"
    )
    assert bytes_pinned != bytes_latest, (
        "the pinned version and $LATEST served byte-identical archives even though their reported "
        f"CodeSha256 values differ ({reported_v1!r} vs {reported_v2!r}) — one of the two URLs is "
        "serving the wrong artifact"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _b64_sha256(payload: bytes) -> str:
    return base64.b64encode(hashlib.sha256(payload).digest()).decode()


def _zip_member(archive: bytes, member: str) -> str:
    """Read one member out of a downloaded archive. Raises with the namelist if it is absent."""
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        names = zf.namelist()
        if member not in names:
            raise AssertionError(
                f"the downloaded deployment package has no {member!r} member; namelist={names}"
            )
        return zf.read(member).decode()


def _download(ctx, url: str, timeout_s: float = 60.0) -> bytes:
    """GET a presigned URL with no credentials attached and return the body bytes.

    A transport failure is reported with DATAPLANE_MARKER: the URL was issued by the target itself.
    """
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, method="GET", headers=route)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(ctx.http_verify)) as resp:
            assert resp.status == 200, f"presigned GET returned HTTP {resp.status} for {url!r}"
            return resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()[:300].decode("utf-8", errors="replace")
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the presigned Code.Location returned HTTP {exc.code}: {body!r}"
        ) from exc
    except urllib.error.URLError as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the presigned Code.Location did not answer at all: {exc.reason}"
        ) from exc


def _create_execution_role(ctx, iam) -> str:
    """Create this check's own execution role, tagged so any leftover can be found by tag."""
    role_name = ctx.unique_name("sim2real-behav-codeloc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal.

    A brand-new IAM role is not immediately assumable by lambda.amazonaws.com, and Lambda answers
    InvalidParameterValueException("The role defined for the function cannot be assumed"). Bounded
    retry with a deadline; raises the last error rather than returning."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(ctx, lam, name))
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _delete_function(ctx, lam, name: str) -> None:
    lam.delete_function(FunctionName=name)
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        # The function is never invoked, so Lambda may never have created its log group.
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    """Wait for State=Active. Raises on timeout and refuses to treat Failed as terminal-good."""
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} "
                f"{cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
    )


def _wait_last_update_successful(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} update failed: {cfg.get('LastUpdateStatusReasonCode')} "
                f"{cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("LastUpdateStatus") == "Successful" and cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching LastUpdateStatus=Successful",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout — never returns its last value, which
    would let a target that never converges pass whatever assertion follows."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
