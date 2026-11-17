"""publish-version-and-list-versions-on-missing-function-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-and-list-versions-on-missing-function-rejected"
GROUP = "versions_aliases"
SERVICES = ["iam", "lambda"]

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


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pvm-role-")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(
            RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        ), "NoSuchEntity"))
    return role["Arn"]


def _create_function(lam, **kwargs):
    """CreateFunction, retried only on the documented role-propagation refusal."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _wait_active(lam, fn, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.5)
    raise AssertionError(f"{fn} did not reach Active within {timeout_s}s; last={last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishVersion and ListVersionsByFunction on a function name nobody ever created
    both raise ResourceNotFoundException naming that function's ARN, while both succeed on a
    function that exists.
    """
    lam = ctx.client("lambda")
    missing_fn = ctx.unique_name("sim2real-behav-pvm-missing-")
    expected_missing_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{missing_fn}"
    )

    code, message = _error(lambda: lam.publish_version(FunctionName=missing_fn, Description="x"))
    assert code == "ResourceNotFoundException", f"PublishVersion on a missing function gave {code!r}"
    assert message == expected_missing_message, (
        f"PublishVersion on a missing function: expected {expected_missing_message!r}, got {message!r}"
    )

    code, message = _error(lambda: lam.list_versions_by_function(FunctionName=missing_fn))
    assert code == "ResourceNotFoundException", (
        f"ListVersionsByFunction on a missing function gave {code!r}"
    )
    assert message == expected_missing_message, (
        f"ListVersionsByFunction on a missing function: expected {expected_missing_message!r}, "
        f"got {message!r}"
    )

    # Positive control: the same two calls succeed, and the given Description sticks, against
    # a function this check actually created.
    role_arn = _create_role(ctx)
    fn = ctx.unique_name("sim2real-behav-pvm-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn}"))
    _create_function(
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zip("def handler(e, c):\n    return {'v': 1}\n")},
        MemorySize=128,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    _wait_active(lam, fn)

    published = lam.publish_version(FunctionName=fn, Description="present")
    assert published["Version"] == "1", f"expected the first publish to be version '1', got {published['Version']!r}"
    assert published["Description"] == "present", (
        f"expected Description 'present' on the function this check created, got {published['Description']!r}"
    )

    versions = [v["Version"] for v in lam.list_versions_by_function(FunctionName=fn)["Versions"]]
    assert versions == ["$LATEST", "1"], (
        f"expected ListVersionsByFunction to report $LATEST and '1', got {versions!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
