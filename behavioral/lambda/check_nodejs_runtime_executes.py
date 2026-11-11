"""nodejs-runtime-executes."""

from __future__ import annotations

import hashlib
import io
import json
import time

from behavioral_harness import tags


CHECK = "nodejs-runtime-executes"
GROUP = 'packaging'
SERVICES = ['lambda']


_ROLES: dict = {}
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
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
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = _BASIC_EXEC.format(partition=_partition(ctx))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


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
    """Delete the function URL, the function and its log group; only an already-gone resource
    (ResourceNotFoundException) is tolerated."""
    from botocore.exceptions import ClientError

    for delete in (
        lambda: lam.delete_function_url_config(FunctionName=name),
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=60):
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


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    assert resp.get("StatusCode") == 200, f"Invoke {fn}: expected StatusCode 200, got {resp.get('StatusCode')!r}"
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A zip Node.js function runs its handler: for two payloads it returns the sorted keys and the
    node:crypto sha256 of the canonical JSON, which an echo of the event cannot produce. The deleted
    function is then not found, unlisted and refuses Invoke."""
    lam = ctx.client("lambda")
    import zipfile as zf

    js_code = (
        "const crypto = require('crypto');\n"
        "exports.handler = async (event) => {\n"
        "  const canonical = JSON.stringify(event, Object.keys(event).sort());\n"
        "  const sha256 = crypto.createHash('sha256').update(canonical).digest('hex');\n"
        "  return { runtime: 'nodejs', keys: Object.keys(event).sort(), sha256 };\n"
        "};\n"
    )
    buf = io.BytesIO()
    with zf.ZipFile(buf, "w") as z:
        z.writestr("index.js", js_code)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    create_resp = _create_function(lam,
        FunctionName=fn_name,
        Runtime="nodejs22.x",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": buf.getvalue()},
        Tags={"sim2real": "nodejs-runtime-executes"},
    )
    ctx.on_cleanup(lambda n=fn_name: _cleanup_fn(ctx, lam, n))
    assert create_resp["Runtime"] == "nodejs22.x", (
        f"CreateFunction echoed Runtime={create_resp.get('Runtime')!r}, expected 'nodejs22.x'"
    )
    _wait_active(lam, fn_name)

    # Flat ASCII payloads, so Python's canonical form and the handler's agree byte for byte.
    second = {"zeta": ctx.unique_name("z-"), "alpha": "first-key", "mid": 7}
    for payload in ({"a": 1, "b": 2}, second):
        expected_sha256 = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        resp = _invoke_sync(lam, fn_name, payload)
        assert isinstance(resp, dict), f"handler returned {resp!r} for {payload!r}, expected an object"
        assert resp.get("runtime") == "nodejs", (
            f"handler reported runtime={resp.get('runtime')!r}, expected 'nodejs'"
        )
        assert resp.get("keys") == sorted(payload), (
            f"handler reported keys={resp.get('keys')!r} for {payload!r}, expected {sorted(payload)!r}"
        )
        assert resp.get("sha256") == expected_sha256, (
            f"handler's crypto.createHash('sha256') digest of the canonicalized event {payload!r} was "
            f"{resp.get('sha256')!r}, expected {expected_sha256!r}: the running code did not hash "
            f"the event it received"
        )

    # Deleted: not found by name, absent from the listing, and Invoke refused.
    from botocore.exceptions import ClientError

    fn_arn = create_resp["FunctionArn"]
    lam.delete_function(FunctionName=fn_name)
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.get_function(FunctionName=fn_name)
        except ClientError as exc:
            _assert_not_found(exc, f"GetFunction {fn_name}", f"Function not found: {fn_arn}")
            break
        assert time.monotonic() < deadline, f"GetFunction {fn_name} still answers 120s after the delete"
        time.sleep(1.0)
    listed = {f["FunctionName"] for page in lam.get_paginator("list_functions").paginate()
              for f in page.get("Functions", [])}
    assert fn_name not in listed, f"ListFunctions still lists the deleted function {fn_name}"
    # Invoke keeps reaching a just-deleted function for a while on AWS, so a success is retried.
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.invoke(FunctionName=fn_name, Payload=b"{}")
        except ClientError as exc:
            _assert_not_found(exc, f"Invoke {fn_name}", f"Function not found: {fn_arn}:$LATEST")
            break
        assert time.monotonic() < deadline, f"Invoke {fn_name}: still succeeds 120s after the delete"
        time.sleep(5)


def _assert_not_found(exc, what: str, expected_msg: str) -> None:
    """Grade a refusal as ResourceNotFoundException, HTTP 4xx, and its exact message."""
    err = exc.response.get("Error", {})
    code, msg = err.get("Code"), err.get("Message") or ""
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "ResourceNotFoundException", f"{what}: expected ResourceNotFoundException, got {code!r}: {msg!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected HTTP 4xx, got {status!r}"
    assert msg == expected_msg, f"{what}: expected message {expected_msg!r}, got {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
