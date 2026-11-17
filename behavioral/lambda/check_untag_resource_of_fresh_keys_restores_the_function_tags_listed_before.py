"""untag-resource-of-fresh-keys-restores-the-function-tags-listed-before."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-of-fresh-keys-restores-the-function-tags-listed-before"
GROUP = "tagging"
SERVICES = ["lambda"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_PENDING = "The role defined for the function cannot be assumed by Lambda."


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _undo(delete, *gone_codes):
    """A cleanup calling delete(); it returns on the resource's own not-found codes, else raises."""

    def run_undo() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in gone_codes:
                raise

    return run_undo


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "def handler(event, context):\n    return event\n")
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role for a function that is never invoked; returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lfuf-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]["Arn"]
    ctx.on_cleanup(_undo(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create(ctx, lam, **params) -> None:
    """CreateFunction, repeated only while IAM has not yet made the new role assumable."""
    deadline = time.monotonic() + _wait_cap(ctx, 120.0)
    for attempt in range(10):
        try:
            lam.create_function(**params)
            break
        except ClientError as exc:
            last = attempt == 9 or time.monotonic() >= deadline
            if exc.response["Error"]["Message"] != _ROLE_PENDING or last:
                raise
        time.sleep(min(2 ** attempt, 20))
    name = params["FunctionName"]
    ctx.on_cleanup(_undo(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))


def _tags_until(ctx, lam, arn: str, want: dict) -> dict:
    """ListTags repeated until it lists exactly want or the wait runs out; the last map read."""
    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    while True:
        got = lam.list_tags(Resource=arn)["Tags"]
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _settled_arn(ctx, lam, name: str) -> str:
    """The function's ARN once it is Active."""
    deadline = time.monotonic() + _wait_cap(ctx, 120.0)
    while True:
        config = lam.get_function_configuration(FunctionName=name)
        if config.get("State") == "Active" or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert config.get("State") == "Active", f"the function settled at State={config.get('State')!r}"
    return config["FunctionArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource of two keys the function did not carry, then UntagResource of those keys, leaves
    ListTags with exactly the tags it listed before, creation tags included.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lfuf-")
    created = {"sim2real": CHECK, "owner": "lab"}
    _create(
        ctx, lam, FunctionName=name, Runtime="python3.13", Role=_role(ctx), Handler="app.handler",
        Code={"ZipFile": _zip()}, Tags=dict(created),
    )
    arn = _settled_arn(ctx, lam, name)

    before = _tags_until(ctx, lam, arn, created)
    assert before == created, f"a function created with tags {created!r} lists {before!r}"

    fresh = {"extra-a": "one", "extra-b": "two"}
    lam.tag_resource(Resource=arn, Tags=fresh)
    tagged = {**before, **fresh}
    got = _tags_until(ctx, lam, arn, tagged)
    assert got == tagged, f"after tagging {sorted(fresh)!r} the function lists {got!r}, expected {tagged!r}"

    lam.untag_resource(Resource=arn, TagKeys=sorted(fresh))
    got = _tags_until(ctx, lam, arn, before)
    assert got == before, f"untagging {sorted(fresh)!r} left {got!r}, expected the earlier set {before!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
