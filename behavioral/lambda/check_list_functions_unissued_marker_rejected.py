"""list-functions-unissued-marker-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-functions-unissued-marker-rejected"
GROUP = "pagination"
SERVICES = ["lambda"]

_UNISSUED = "bm90LWEtbWFya2Vy"
_EXPECTED_CODE = "InvalidParameterValueException"
_EXPECTED_MESSAGE = f"Invalid marker value: {_UNISSUED}"
_PAGE_CAP = 5000  # a walk that never drops NextMarker fails instead of spinning
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _paced(ctx, fn):
    """fn(), retried while Lambda throttles the call on the account."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown(undo, *not_found):
    """A cleanup running undo() that returns on the resource's own not-found codes and raises otherwise."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in not_found:
                raise

    return run_undo


def _package() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "def handler(event, context):\n    return {}\n")
    return buf.getvalue()


def _execution_role(ctx) -> str:
    """A role Lambda may assume and nothing else; the functions here are never invoked."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lfm-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_function(ctx, lam, role_arn: str, name: str) -> None:
    """CreateFunction, retried only while the new role is not yet assumable by Lambda."""
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.13", Role=role_arn, Handler="app.handler",
                Code={"ZipFile": _package()}, MemorySize=128, Timeout=3,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Message"] != _ROLE_NOT_READY or time.monotonic() >= deadline:
                raise
        time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctions refuses a Marker it never issued with InvalidParameterValueException and its
    exact message, while the NextMarker it did issue resumes the walk to its last page.
    """
    lam = ctx.client("lambda")
    role_arn = _execution_role(ctx)
    stem = ctx.unique_name("sim2real-lfm-")
    own = sorted(f"{stem}-{i}" for i in range(2))
    for name in own:
        _create_function(ctx, lam, role_arn, name)

    first = _paced(ctx, lambda: lam.list_functions(MaxItems=1))
    issued = first.get("NextMarker")
    assert issued, f"MaxItems=1 over at least two functions returned no NextMarker: {sorted(first)!r}"
    listed = [f["FunctionName"] for f in first.get("Functions", [])]
    marker = issued
    while marker:
        assert len(listed) < _PAGE_CAP, f"ListFunctions still returned a NextMarker after {len(listed)} pages"
        page = _paced(ctx, lambda: lam.list_functions(MaxItems=1, Marker=marker))
        listed += [f["FunctionName"] for f in page.get("Functions", [])]
        marker = page.get("NextMarker")
    walked = sorted(n for n in listed if n in own)
    assert walked == own, f"the walk resumed from the issued NextMarker listed {walked!r}, expected {own!r}"

    got = _refusal(lambda: _paced(ctx, lambda: lam.list_functions(MaxItems=1, Marker=_UNISSUED)))
    assert got == (_EXPECTED_CODE, _EXPECTED_MESSAGE), (
        f"a Marker ListFunctions never issued gave {got!r}, expected {(_EXPECTED_CODE, _EXPECTED_MESSAGE)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
