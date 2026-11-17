"""publish-version-description-tracked-per-version-through-list-and-qualified-read."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-description-tracked-per-version-through-list-and-qualified-read"
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
    name = ctx.unique_name("sim2real-behav-pvd-role-")
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


def _wait_updated(lam, fn, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"function {fn} update failed: {last.get('LastUpdateStatusReason')}")
        if status == "Successful":
            return
        time.sleep(1.5)
    raise AssertionError(f"{fn} update did not settle within {timeout_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishVersion, ListVersionsByFunction and a qualified GetFunctionConfiguration each
    report a version's own Description, and republishing with nothing changed returns the
    existing version with its Description unchanged rather than minting a new one.
    """
    lam = ctx.client("lambda")
    role_arn = _create_role(ctx)
    fn = ctx.unique_name("sim2real-behav-pvd-fn-")

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
        Description="unpublished",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    _wait_active(lam, fn)

    v1 = lam.publish_version(FunctionName=fn, Description="first")
    assert v1["Version"] == "1", f"first publish should be version '1', got {v1['Version']!r}"
    assert v1["Description"] == "first", f"expected Description 'first' on publish, got {v1['Description']!r}"

    lam.update_function_code(FunctionName=fn, ZipFile=_zip("def handler(e, c):\n    return {'v': 2}\n"))
    _wait_updated(lam, fn)

    v2 = lam.publish_version(FunctionName=fn, Description="second")
    assert v2["Version"] == "2", f"second publish should be version '2', got {v2['Version']!r}"
    assert v2["Description"] == "second", f"expected Description 'second' on publish, got {v2['Description']!r}"

    listed = lam.list_versions_by_function(FunctionName=fn)["Versions"]
    got_order = [(entry["Version"], entry["Description"]) for entry in listed]
    want_order = [("$LATEST", "unpublished"), ("1", "first"), ("2", "second")]
    assert got_order == want_order, (
        f"ListVersionsByFunction should report $LATEST, 1 and 2 in that order with their own "
        f"Description, got {got_order!r}"
    )

    qualified = lam.get_function_configuration(FunctionName=fn, Qualifier="1")
    assert qualified["Version"] == "1", f"Qualifier='1' should read version '1', got {qualified['Version']!r}"
    assert qualified["Description"] == "first", (
        f"GetFunctionConfiguration Qualifier='1' should report Description 'first', "
        f"got {qualified['Description']!r}"
    )

    again = lam.publish_version(FunctionName=fn)
    assert again["Version"] == "2", (
        f"publishing with nothing changed since version 2 should return the existing version '2', "
        f"got {again['Version']!r}"
    )
    assert again["Description"] == "second", (
        f"the existing version returned unchanged should keep its own Description 'second', "
        f"got {again['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
