"""delete-function-version-referenced-by-alias-conflict."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-function-version-referenced-by-alias-conflict"
GROUP = "versions_aliases"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFunction with a Qualifier for a version still referenced by an alias must fail,
    not silently succeed — and the version must survive the rejected call, be deletable the
    moment the alias is gone, and be truly gone (and unusable) afterward."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-alias-del-")
    _create_function(ctx, lam, name=name)
    _wait_active(lam, name)

    v1 = lam.publish_version(FunctionName=name)["Version"]

    # PublishVersion is a no-op that returns the existing version when code/config are
    # unchanged since the last publish, so v2 needs a real code change to be distinct from v1.
    lam.update_function_code(FunctionName=name, ZipFile=_make_zip(_DEFAULT_HANDLER_SRC + "\n# v2\n"))
    _wait_update_settled(lam, name)
    v2 = lam.publish_version(FunctionName=name)["Version"]
    assert v2 != v1, f"expected a distinct version after a real code change, got {v2} == {v1}"

    # Positive control: deleting a version with no alias pointing at it succeeds outright, so
    # the conflict asserted below is specific to the alias reference, not a general inability
    # to delete a version.
    fn_arn = lam.get_function_configuration(FunctionName=name)["FunctionArn"]
    lam.delete_function(FunctionName=name, Qualifier=v2)
    control_gone, control_gone_msg = _client_error(lambda: lam.get_function(FunctionName=name, Qualifier=v2))
    assert control_gone == "ResourceNotFoundException", (
        f"expected version {v2} to be gone after its own delete, got {control_gone}"
    )
    expected_v2_missing = f"Function not found: {fn_arn}:{v2}"
    assert control_gone_msg == expected_v2_missing, (
        f"expected message {expected_v2_missing!r}, got {control_gone_msg!r}"
    )

    # Break: v1 is now referenced by an alias.
    lam.create_alias(FunctionName=name, Name="pin", FunctionVersion=v1)

    code, msg = _client_error(lambda: lam.delete_function(FunctionName=name, Qualifier=v1))
    assert code == "ResourceConflictException", f"expected ResourceConflictException, got {code}"
    expected_conflict = "Unable to delete version because the following aliases reference it: [pin]"
    assert msg == expected_conflict, f"expected message {expected_conflict!r}, got {msg!r}"

    # Effect absent: the rejected delete must not have touched v1 — an independent read still
    # finds it.
    still_there = lam.get_function(FunctionName=name, Qualifier=v1)
    assert still_there["Configuration"]["Version"] == v1, (
        f"expected version {v1} to still exist after the rejected delete, got {still_there['Configuration']!r}"
    )

    # Restore: remove the alias, then the identical call must now succeed.
    lam.delete_alias(FunctionName=name, Name="pin")
    lam.delete_function(FunctionName=name, Qualifier=v1)

    # Deletes prove gone and unusable: an independent read 404s, and a mutation naming the dead
    # version also fails.
    expected_v1_missing = f"Function not found: {fn_arn}:{v1}"
    gone_code, gone_msg = _client_error(lambda: lam.get_function(FunctionName=name, Qualifier=v1))
    assert gone_code == "ResourceNotFoundException", f"expected {v1} to be gone, got {gone_code}"
    assert gone_msg == expected_v1_missing, f"expected message {expected_v1_missing!r}, got {gone_msg!r}"
    dead_mutation_code, dead_mutation_msg = _client_error(
        lambda: lam.create_alias(FunctionName=name, Name="ghost", FunctionVersion=v1)
    )
    assert dead_mutation_code == "ResourceNotFoundException", (
        f"expected aliasing the deleted version {v1} to fail, got {dead_mutation_code}"
    )
    assert dead_mutation_msg == expected_v1_missing, (
        f"expected message {expected_v1_missing!r}, got {dead_mutation_msg!r}"
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


_ROLE_ARNS: dict = {}


def _role_arn(ctx):
    key = id(ctx)
    if key not in _ROLE_ARNS:
        iam = ctx.client("iam")
        role_name = ctx.unique_name("sim2real-behav-role-")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        _ROLE_ARNS[key] = role["Role"]["Arn"]
    return _ROLE_ARNS[key]


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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

    A Failed function is not raised here; it surfaces as a service error on the next call.
    """
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
    )


def _wait_update_settled(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    """Poll until a code/config update leaves Pending — required before the next
    PublishVersion, since Lambda refuses to publish while an update is in flight."""
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("LastUpdateStatus") in ("Successful", "Failed"),
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
        Tags={"sim2real:managed": "true"},
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    last_exc = None
    for _ in range(8):
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
