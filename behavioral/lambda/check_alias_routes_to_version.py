"""alias-routes-to-version."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags


CHECK = "alias-routes-to-version"
GROUP = 'versions_aliases'
SERVICES = ['lambda']
#: The default service-class budget for a poll; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
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


def _cleanup_fn(ctx, lam, name):
    """Teardown: function URL, function and log group; only ResourceNotFoundException (absent
    already) is tolerated, every other error raises."""
    from botocore.exceptions import ClientError

    for step in (
        lambda: lam.delete_function_url_config(FunctionName=name),
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            step()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=POLL_BUDGET_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _wait_updated(lam, fn, timeout_s=POLL_BUDGET_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"{fn} code update failed: {last.get('LastUpdateStatusReason')}")
        if status == "Successful":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} LastUpdateStatus not Successful within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Invoke through an alias pinned to an older version runs that version (ExecutedVersion and body
    marker v1) while an unqualified invoke runs the newer $LATEST; after DeleteAlias, GetAlias and
    Invoke through it are ResourceNotFoundException with exact messages and ListAliases omits it."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return {'marker': 'v1'}")
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip("def handler(e, c): return {'marker': 'v2'}"))
    _wait_updated(lam, fn)
    v2 = lam.publish_version(FunctionName=fn)["Version"]
    assert v1 != v2, f"publish_version must mint a fresh version number, got {v1!r} both times"

    alias_arn = lam.create_alias(FunctionName=fn, Name="live", FunctionVersion=v1)["AliasArn"]
    pinned = lam.get_alias(FunctionName=fn, Name="live")["FunctionVersion"]
    assert pinned == v1, f"GetAlias reports alias 'live' at version {pinned!r}, expected {v1!r}"

    resp = lam.invoke(FunctionName=f"{fn}:live", Payload=b"{}")
    executed = resp.get("ExecutedVersion")
    assert executed == v1, (
        f"alias 'live' is pinned to version {v1!r} but invoke reported ExecutedVersion={executed!r}"
    )
    body = json.loads(resp["Payload"].read())
    assert body.get("marker") == "v1", (
        f"alias 'live' is pinned to version {v1!r} (marker 'v1') but the code that actually ran "
        f"returned {body!r} -- the reported version and the executed code disagree"
    )

    latest_resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    latest_body = json.loads(latest_resp["Payload"].read())
    assert latest_body.get("marker") == "v2", (
        f"$LATEST was updated to the marker-'v2' code after {v1!r} was published, so an "
        f"unqualified invoke must return {{'marker': 'v2'}}, got {latest_body!r} -- if this also "
        f"reads 'v1' the alias invoke above proved nothing, since both would be running the same code"
    )

    lam.delete_alias(FunctionName=fn, Name="live")
    # Gone beat 1: GetAlias answers ResourceNotFoundException naming the alias.
    refused = _error(lambda: lam.get_alias(FunctionName=fn, Name="live"))
    _assert_error(refused, "ResourceNotFoundException", 404, "live")
    expected_message = f"Cannot find alias arn: {alias_arn}"
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'
    # Gone beat 2: the function's alias listing no longer contains it.
    aliases = [a["Name"] for page in lam.get_paginator("list_aliases").paginate(FunctionName=fn) for a in page["Aliases"]]
    assert "live" not in aliases, f"deleted alias still listed by ListAliases: {aliases!r}"
    # Gone beat 3: invoking through the dead alias is refused.
    refused = _error(lambda: lam.invoke(FunctionName=f"{fn}:live", Payload=b"{}"))
    _assert_error(refused, "ResourceNotFoundException", 404)
    expected_message = f"Function not found: {alias_arn}"
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'


def _error(fn):
    """Call fn() and return its ClientError response; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _assert_error(resp, code, status, subject=None):
    """Grade a refusal on code + HTTP status + the exact message (naming the subject if given)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
    assert got_status == status, f"expected HTTP {status} for {code}, got {got_status!r}"
    assert err.get("Message"), f"expected a non-empty {code} message, got {err!r}"
    if subject is not None:
        assert subject in err["Message"], f"expected the {code} message to name {subject!r}, got {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
