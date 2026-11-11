"""published-version-tracing-config-pinned-through-latest-change."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "published-version-tracing-config-pinned-through-latest-change"
GROUP = "function_config"
SERVICES = ["lambda"]

RUNTIME = "python3.13"
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"

HANDLER = "def handler(event, context):\n    return event\n"


def _teardown(undo, *not_found: str):
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


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(source))
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role (basic logging only), deleted in its teardown."""
    name = ctx.unique_name("sim2real-behav-trc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_active(ctx, lam, name, qualifier=None) -> dict:
    args = {"FunctionName": name}
    if qualifier:
        args["Qualifier"] = qualifier
    timeout_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + timeout_s
    while True:
        conf = lam.get_function_configuration(**args)
        if conf.get("State") == "Failed" or conf.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} ({qualifier}) failed: {conf.get('StateReason')} "
                f"{conf.get('LastUpdateStatusReason')}"
            )
        if conf.get("State", "Active") == "Active" and conf.get(
            "LastUpdateStatus", "Successful"
        ) in (None, "Successful"):
            return conf
        if time.monotonic() > deadline:
            raise TimeoutError(f"{name} ({qualifier}) did not settle within {timeout_s:.0f}s: {conf!r}")
        time.sleep(1.0)


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or (
                _ROLE_PROPAGATION not in msg
            ):
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"CreateFunction kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_active(ctx, lam, name)
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A version published while TracingConfig.Mode=Active keeps Mode=Active after $LATEST is
    switched to PassThrough: the version is an independent, immutable snapshot of the config it
    was published with, not a live view of $LATEST.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_PublishVersion.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-trc-")
    _create_function(
        ctx, lam, logs,
        FunctionName=name, Runtime=RUNTIME, Role=_make_role(ctx, ctx.client("iam")),
        Handler="index.handler", Code={"ZipFile": _zip("index.py", HANDLER)},
        MemorySize=128, Timeout=10, TracingConfig={"Mode": "Active"},
        Tags={"sim2real": CHECK},
    )
    latest_before = lam.get_function_configuration(FunctionName=name)
    assert latest_before["TracingConfig"]["Mode"] == "Active", (
        f"$LATEST must start Active, got {latest_before['TracingConfig']!r}"
    )

    published = lam.publish_version(FunctionName=name)
    version = published["Version"]
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=name, Qualifier=version),
        "ResourceNotFoundException"))
    assert published["TracingConfig"]["Mode"] == "Active", (
        f"PublishVersion response must carry Mode=Active, got {published['TracingConfig']!r}"
    )
    version_conf = _wait_active(ctx, lam, name, qualifier=version)
    assert version_conf["TracingConfig"]["Mode"] == "Active", (
        f"independent read of the published version must show Mode=Active, "
        f"got {version_conf['TracingConfig']!r}"
    )

    lam.update_function_configuration(FunctionName=name, TracingConfig={"Mode": "PassThrough"})
    latest_after = _wait_active(ctx, lam, name)
    assert latest_after["TracingConfig"]["Mode"] == "PassThrough", (
        f"$LATEST must now read PassThrough, got {latest_after['TracingConfig']!r}"
    )

    version_conf_after = lam.get_function_configuration(FunctionName=name, Qualifier=version)
    assert version_conf_after["TracingConfig"]["Mode"] == "Active", (
        f"the published version must still read Active after $LATEST changed to PassThrough, "
        f"got {version_conf_after['TracingConfig']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
