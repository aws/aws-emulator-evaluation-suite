"""list-functions-item-agrees-with-get-function."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-functions-item-agrees-with-get-function"
GROUP = "representation"
SERVICES = ["lambda"]

_PAGE_CAP = 200  # a walk whose token never ends fails instead of spinning

# FunctionConfiguration members both views name. ListFunctions is documented to leave out the
# state and update-status fields and RuntimeVersionConfig, so those are not compared.
_SHARED = (
    "Architectures", "CapacityProviderConfig", "CodeSha256", "CodeSize", "ConfigSha256",
    "DeadLetterConfig", "Description", "DurableConfig", "Environment", "EphemeralStorage",
    "FileSystemConfigs", "FunctionArn", "FunctionName", "Handler", "ImageConfigResponse",
    "KMSKeyArn", "LastModified", "Layers", "LoggingConfig", "MasterArn", "MemorySize",
    "PackageType", "RevisionId", "Role", "Runtime", "SigningJobArn", "SigningProfileVersionArn",
    "SnapStart", "TenancyConfig", "Timeout", "TracingConfig", "Version", "VpcConfig",
)
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


def _throttled(ctx, call):
    """call(), repeated while Lambda answers TooManyRequestsException for the account."""
    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    for attempt in range(10):
        try:
            return call()
        except ClientError as exc:
            last = attempt == 9 or time.monotonic() >= deadline
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or last:
                raise
        time.sleep(min(2 ** attempt, 16))


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "def handler(event, context):\n    return event\n")
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role for a function that is never invoked; returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lfag-role-")
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


def _listed(ctx, lam, name: str):
    """The ListFunctions item for name, walking every page, or None when no page lists it."""
    kwargs: dict = {"MaxItems": 50}
    for _ in range(_PAGE_CAP):
        page = _throttled(ctx, lambda: lam.list_functions(**kwargs))
        for item in page.get("Functions", []):
            if item["FunctionName"] == name:
                return item
        if not page.get("NextMarker"):
            return None
        kwargs["Marker"] = page["NextMarker"]
    raise AssertionError(f"ListFunctions still returned a NextMarker after {_PAGE_CAP} pages")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The ListFunctions item for a settled function equals GetFunction's Configuration on every
    field both views share, so a listing never reports a stale or different configuration.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lfag-")
    _create(
        ctx, lam, FunctionName=name, Runtime="python3.13", Role=_role(ctx), Handler="app.handler",
        Code={"ZipFile": _zip()}, Description="list and read agree", MemorySize=256, Timeout=9,
        Architectures=["arm64"], Environment={"Variables": {"MODE": "check"}}, Tags={"sim2real": CHECK},
    )

    deadline = time.monotonic() + _wait_cap(ctx, 120.0)
    while True:
        config = lam.get_function(FunctionName=name)["Configuration"]
        settled = (config.get("State"), config.get("LastUpdateStatus")) == ("Active", "Successful")
        if settled or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert settled, f"the function settled at {(config.get('State'), config.get('LastUpdateStatus'))!r}"

    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    while True:
        read = {f: config[f] for f in _SHARED if f in config}
        item = _listed(ctx, lam, name)
        listed = None if item is None else {f: item.get(f) for f in read}
        if listed == read or time.monotonic() >= deadline:
            break
        time.sleep(5)
        config = lam.get_function(FunctionName=name)["Configuration"]

    assert item is not None, f"ListFunctions never listed {name!r}"
    assert {"FunctionName", "Runtime", "Handler", "Environment", "Description"} <= set(read), (
        f"GetFunction's Configuration carried only {sorted(read)!r}"
    )
    differ = {f: {"read": read[f], "list": listed[f]} for f in read if listed[f] != read[f]}
    assert differ == {}, f"ListFunctions disagrees with GetFunction on {differ!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
