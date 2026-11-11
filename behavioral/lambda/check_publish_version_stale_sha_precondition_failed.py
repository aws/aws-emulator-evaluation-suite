"""publish-version-stale-sha-precondition-failed."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-stale-sha-precondition-failed"
GROUP = "versions_aliases"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishVersion rejects a mismatched CodeSha256 (InvalidParameterValueException) and a stale
    RevisionId (PreconditionFailedException) without creating a version; correct preconditions succeed.
    """
    import base64
    import hashlib

    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-stale-")
    resp = _create_function(ctx, lam, name=name)
    _wait_active(lam, name)

    def _versions():
        return [v["Version"] for v in lam.list_versions_by_function(FunctionName=name)["Versions"]]

    assert _versions() == ["$LATEST"], f"expected only $LATEST before any publish, got {_versions()}"

    # 0. Positive control: PublishVersion with the CORRECT CodeSha256 succeeds and is
    #    independently visible, so the two rejections below cannot be "every call fails".
    v1 = lam.publish_version(FunctionName=name, CodeSha256=resp["CodeSha256"])
    assert v1["Version"] != "$LATEST", f"expected a numbered version, got {v1['Version']!r}"
    assert v1["Version"] in _versions(), (
        f"published version {v1['Version']} not visible via ListVersionsByFunction"
    )

    # 1. Well-formed base64 SHA-256, but the digest of some *other* content.
    mismatched_sha = base64.b64encode(hashlib.sha256(b"some other payload").digest()).decode()
    versions_before_mismatch = _versions()
    code, code_msg = _error(
        lambda: lam.publish_version(FunctionName=name, CodeSha256=mismatched_sha)
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for mismatched CodeSha256, got {code}"
    )
    assert code_msg == (
        f"CodeSHA256 ({mismatched_sha}) is different from current CodeSHA256 in $LATEST "
        f"({resp['CodeSha256']}). Please try again with the CodeSHA256 in $LATEST."
    ), (
        f"expected the exact 'InvalidParameterValueException' message, got {code_msg!r}"
    )
    assert _versions() == versions_before_mismatch, (
        f"rejected CodeSha256 must not create a version: before={versions_before_mismatch}, "
        f"after={_versions()}"
    )

    # 2. Stale RevisionId: advance the revision, then publish against the old one.
    stale_revision = v1["RevisionId"]
    lam.update_function_configuration(FunctionName=name, Timeout=25)
    _wait_update_done(lam, name)

    versions_before_stale = _versions()
    code2, code2_msg = _error(
        lambda: lam.publish_version(FunctionName=name, RevisionId=stale_revision)
    )
    assert code2 == "PreconditionFailedException", (
        f"expected PreconditionFailedException for stale RevisionId, got {code2}"
    )
    assert code2_msg == (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    ), (
        f"expected the exact 'PreconditionFailedException' message, got {code2_msg!r}"
    )
    assert _versions() == versions_before_stale, (
        f"rejected stale-revision publish must not create a version: before={versions_before_stale}, "
        f"after={_versions()}"
    )

    # Restore: the identical call against the now-current RevisionId succeeds.
    fresh_revision = lam.get_function_configuration(FunctionName=name)["RevisionId"]
    v2 = lam.publish_version(FunctionName=name, RevisionId=fresh_revision)
    assert v2["Version"] not in ("$LATEST", v1["Version"]), (
        f"expected a new numbered version distinct from {v1['Version']}, got {v2['Version']!r}"
    )
    assert v2["Version"] in _versions(), (
        f"published version {v2['Version']} not visible via ListVersionsByFunction after restore"
    )


_DEFAULT_HANDLER_SRC = """
import json

def handler(event, context):
    if isinstance(event, dict) and event.get("fail"):
        raise Exception("intentional-failure: " + str(event.get("fail")))
    return {"echo": event}
"""


def _make_zip(src: str = _DEFAULT_HANDLER_SRC, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _cleanup_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group Lambda implicitly creates for it."""
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    """Poll until State settles at Active or Failed.

    Does not raise on Failed: a Failed function surfaces as a service error on the next call.
    """
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
    )


def _wait_update_done(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("LastUpdateStatus") in ("Successful", "Failed", None),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} update to settle",
    )


def _create_function(
    ctx,
    lam,
    name=None,
    src: str = _DEFAULT_HANDLER_SRC,
    handler: str = "index.handler",
    runtime: str = "python3.12",
    timeout: int = 15,
    memory: int = 128,
    role_arn: str | None = None,
    env: dict | None = None,
    **kwargs,
):
    """CreateFunction with teardown registered up front and bounded retry on IAM
    role propagation (the classic "cannot be assumed by Lambda" race)."""
    name = name or ctx.unique_name("sim2real-behav-lambda-fn-")
    params = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn or _role_arn(ctx),
        Handler=handler,
        Code={"ZipFile": _make_zip(src)},
        Timeout=timeout,
        MemorySize=memory,
        Publish=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-lambda-stale-"},
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    left = ctx.time_left()
    deadline = time.monotonic() + (90.0 if left is None else min(90.0, left))
    while True:
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            role_not_ready = "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            )
            if not role_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
