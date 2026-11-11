"""delete-latest-qualifier-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-latest-qualifier-rejected"
GROUP = 'versions_aliases'
SERVICES = ["lambda", "iam"]

CODE = """\
MARKER = "%s"


def handler(event, context):
    return {"marker": MARKER}
"""
# Measured on real Lambda: a deleted version can keep answering invokes for a few seconds.
GONE_TIMEOUT_S = 60


def _until_refused(call):
    """(code, message, status) of the first refusal of ``call`` within GONE_TIMEOUT_S; a call
    that keeps succeeding past the deadline raises, quoting the last success."""
    deadline = time.monotonic() + GONE_TIMEOUT_S
    while True:
        try:
            result = call()
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"),
                    exc.response["ResponseMetadata"]["HTTPStatusCode"])
        if time.monotonic() > deadline:
            payload = result["Payload"].read() if hasattr(result.get("Payload"), "read") else None
            raise AssertionError(
                f"still answered {GONE_TIMEOUT_S}s after the delete: "
                f"ExecutedVersion={result.get('ExecutedVersion')!r} payload={payload!r}"
            )
        time.sleep(1)


_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip(files: dict) -> bytes:
    """A deterministic archive: fixed timestamps and modes, so equal sources give equal bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role. It carries no policy: the handlers write no logs, so
    Lambda creates no /aws/lambda/<fn> log group that could outlive the check."""
    name = ctx.unique_name("sim2real-behav-l6-")
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs) -> dict:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits until ready."""
    name = kwargs["FunctionName"]
    deadline = time.monotonic() + 90.0
    while True:
        try:
            created = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or err.get("Message") != _ROLE_NOT_READY:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction kept failing on role propagation: {err!r}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return created


def _wait_ready(lam, name: str, qualifier: str = "$LATEST", timeout_s: float = 120.0) -> dict:
    """Poll until the function (or one version of it) is Active with its last update Successful."""
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name, Qualifier=qualifier)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{qualifier} failed: {cfg.get('StateReason')!r} {cfg.get('LastUpdateStatusReason')!r}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{qualifier} not ready within {timeout_s}s: State={cfg.get('State')!r} "
                f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}"
            )
        time.sleep(1)


def _invoke(lam, target: str, **kwargs):
    """A synchronous invoke that must succeed: returns (ExecutedVersion, decoded body)."""
    resp = lam.invoke(FunctionName=target, Payload=b"{}", **kwargs)
    payload = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"invoke of {kwargs or target!r} returned {resp['StatusCode']!r}"
    assert "FunctionError" not in resp, (
        f"invoke reported FunctionError={resp.get('FunctionError')!r}: {payload!r}"
    )
    return resp.get("ExecutedVersion"), json.loads(payload)


def _error(fn):
    """(code, message, http status) of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"),
                exc.response["ResponseMetadata"]["HTTPStatusCode"])
    if isinstance(result, dict) and hasattr(result.get("Payload"), "read"):
        result = {**result, "Payload": result["Payload"].read()}
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteFunction with Qualifier=$LATEST is refused with InvalidParameterValueException and
    deletes nothing: $LATEST and the published version both keep executing their own code.
    """
    lam = ctx.client("lambda")
    role = _make_role(ctx, ctx.client("iam"))
    fn = ctx.unique_name("sim2real-behav-l6-dellatest-")
    created = _create_function(ctx, lam, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
                               Role=role, Code={"ZipFile": _zip({"index.py": CODE % "published"})},
                               Timeout=10, Tags={"sim2real": CHECK})
    v1 = lam.publish_version(FunctionName=fn)["Version"]
    lam.update_function_code(FunctionName=fn, ZipFile=_zip({"index.py": CODE % "head"}))
    _wait_ready(lam, fn)

    code, message, status = _error(lambda: lam.delete_function(FunctionName=fn, Qualifier="$LATEST"))
    assert (code, status) == ("InvalidParameterValueException", 400), (
        f"DeleteFunction(Qualifier=$LATEST) must be refused with InvalidParameterValueException/400, "
        f"got {(code, status)!r}"
    )
    assert message == "$LATEST version cannot be deleted without deleting the function.", message

    runs = (_invoke(lam, fn), _invoke(lam, fn, Qualifier=v1))
    assert runs == (("$LATEST", {"marker": "head"}), (v1, {"marker": "published"})), (
        f"the refused delete must remove nothing; $LATEST and {v1} ran {runs!r}"
    )
    # Positive control: a published version IS deletable by qualifier, leaving $LATEST.
    lam.delete_function(FunctionName=fn, Qualifier=v1)
    head = _invoke(lam, fn)
    assert head == ("$LATEST", {"marker": "head"}), f"$LATEST must survive deleting {v1}, got {head!r}"

    code, message, status = _until_refused(lambda: lam.invoke(FunctionName=fn, Qualifier=v1, Payload=b"{}"))
    assert (code, status, message) == (
        "ResourceNotFoundException", 404, f"Function not found: {created['FunctionArn']}:{v1}"), (
        f"the deleted version {v1} must not resolve, got {(code, status, message)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
