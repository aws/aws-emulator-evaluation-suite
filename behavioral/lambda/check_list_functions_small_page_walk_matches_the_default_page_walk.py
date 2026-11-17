"""list-functions-small-page-walk-matches-the-default-page-walk."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-functions-small-page-walk-matches-the-default-page-walk"
GROUP = "pagination"
SERVICES = ["lambda"]

_FUNCTIONS = 5
_PAGE = 2
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


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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
    name = ctx.unique_name("sim2real-lfpw-role-")
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


def _walk(ctx, lam, page_size: int | None) -> list[list[str]]:
    """Every ListFunctions page in order, following NextMarker until a page carries none."""
    pages: list[list[str]] = []
    kwargs = {} if page_size is None else {"MaxItems": page_size}
    while True:
        resp = _paced(ctx, lambda: lam.list_functions(**kwargs))
        pages.append([f["FunctionName"] for f in resp.get("Functions", [])])
        marker = resp.get("NextMarker")
        if not marker:
            return pages
        assert len(pages) < _PAGE_CAP, f"ListFunctions still returned a NextMarker after {len(pages)} pages"
        kwargs["Marker"] = marker


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctions walked at MaxItems=2 to its last page lists the check's functions once each,
    exactly as the walk at the default page size lists them.
    """
    lam = ctx.client("lambda")
    role_arn = _execution_role(ctx)
    stem = ctx.unique_name("sim2real-lfpw-")
    own = sorted(f"{stem}-{i}" for i in range(_FUNCTIONS))
    for name in own:
        _create_function(ctx, lam, role_arn, name)

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        whole = [n for page in _walk(ctx, lam, None) for n in page if n in own]
        small = _walk(ctx, lam, _PAGE)
        paged = [n for page in small for n in page if n in own]
        if sorted(whole) == own and sorted(paged) == own:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before both ListFunctions walks listed the functions")
            break
        time.sleep(2)

    assert sorted(whole) == own, (
        f"the default-page walk listed {sorted(whole)!r} of the check's functions, expected {own!r}"
    )
    sizes = [len(page) for page in small]
    assert all(size <= _PAGE for size in sizes), f"a MaxItems={_PAGE} page held more: page sizes {sizes!r}"
    assert len(paged) == len(set(paged)), f"the MaxItems={_PAGE} walk listed a function twice: {paged!r}"
    assert sorted(paged) == sorted(whole), (
        f"the MaxItems={_PAGE} walk listed {sorted(paged)!r}, the default-page walk {sorted(whole)!r}"
    )
    assert len(small) >= 3, f"{_FUNCTIONS} functions at MaxItems={_PAGE} gave only {len(small)} page(s)"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
