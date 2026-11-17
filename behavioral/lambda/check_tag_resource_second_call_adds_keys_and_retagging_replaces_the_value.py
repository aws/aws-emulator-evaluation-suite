"""tag-resource-second-call-adds-keys-and-retagging-replaces-the-value."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-second-call-adds-keys-and-retagging-replaces-the-value"
GROUP = "tagging"
SERVICES = ["lambda"]

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
    name = ctx.unique_name("sim2real-trk-role-")
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


def _settled(ctx, read, want, what: str):
    """read() polled until it equals want or the wait ends; the last read either way."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        got = read()
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended before {what}")
            return got
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second TagResource adds its key beside the keys already set, and re-tagging a present key
    replaces its value; ListTags returns exactly the merged map each time.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-trk-")
    _create_function(ctx, lam, _execution_role(ctx), name)
    state = _settled(
        ctx, lambda: lam.get_function_configuration(FunctionName=name)["State"], "Active",
        "the function left Pending",
    )
    assert state == "Active", f"function reached State={state!r}, expected 'Active'"
    arn = lam.get_function_configuration(FunctionName=name)["FunctionArn"]

    def listed():
        return lam.list_tags(Resource=arn)["Tags"]

    lam.tag_resource(Resource=arn, Tags={"team": "blue", "stage": "test"})
    first = {"team": "blue", "stage": "test"}
    got = _settled(ctx, listed, first, "ListTags showed the first two tags")
    assert got == first, f"after tagging team and stage the function lists {got!r}, expected {first!r}"

    lam.tag_resource(Resource=arn, Tags={"cost": "lab"})
    merged = {**first, "cost": "lab"}
    got = _settled(ctx, listed, merged, "ListTags showed the merged tags")
    assert got == merged, f"a second TagResource left the function listing {got!r}, expected {merged!r}"

    lam.tag_resource(Resource=arn, Tags={"team": "green"})
    replaced = {**merged, "team": "green"}
    got = _settled(ctx, listed, replaced, "ListTags showed the replaced value")
    assert got == replaced, f"re-tagging team left the function listing {got!r}, expected {replaced!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
