"""get-function-returns-each-member-create-function-set."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-function-returns-each-member-create-function-set"
GROUP = "representation"
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
    name = ctx.unique_name("sim2real-lgfm-role-")
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunction returns each configuration member CreateFunction set, with the value sent, once
    the function is Active.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lgfm-")
    role = _role(ctx)
    # Every value but PackageType differs from its default, so a store that drops it is caught.
    sent = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role, "Handler": "app.handler",
        "PackageType": "Zip", "Architectures": ["arm64"], "EphemeralStorage": {"Size": 1024},
        "Timeout": 7, "TracingConfig": {"Mode": "Active"},
    }
    _create(ctx, lam, Code={"ZipFile": _zip()}, Tags={"sim2real": CHECK}, **sent)

    deadline = time.monotonic() + _wait_cap(ctx, 120.0)
    while True:
        config = lam.get_function(FunctionName=name)["Configuration"]
        if config.get("State") == "Active" or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert config.get("State") == "Active", f"the function settled at State={config.get('State')!r}"

    read = {member: config.get(member) for member in sent}
    differ = {m: {"sent": sent[m], "read": read[m]} for m in sent if read[m] != sent[m]}
    assert differ == {}, f"GetFunction does not return what CreateFunction set: {differ!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
