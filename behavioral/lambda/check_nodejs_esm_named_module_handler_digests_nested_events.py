"""nodejs-esm-named-module-handler-digests-nested-events."""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-esm-named-module-handler-digests-nested-events"
GROUP = 'packaging'
SERVICES = ['lambda']

#: Canonical JSON with keys sorted at every depth, compact separators: the same bytes Python's
#: json.dumps(sort_keys=True, separators=(",", ":")) writes for ASCII-only events.
_JS_CODE = (
    "import { createHash } from 'node:crypto';\n"
    "const canon = (v) => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'\n"
    "  : (v !== null && typeof v === 'object')\n"
    "    ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'\n"
    "    : JSON.stringify(v);\n"
    "const depth = (v) => (v !== null && typeof v === 'object')\n"
    "  ? 1 + Math.max(0, ...Object.values(v).map(depth)) : 0;\n"
    "export const digest = async (event) => {\n"
    "  const text = canon(event);\n"
    "  return { module: 'esm', sha256: createHash('sha256').update(text).digest('hex'),\n"
    "           length: text.length, depth: depth(event) };\n"
    "};\n"
)


_ROLES: dict = {}
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _execution_role(ctx):
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
    deadline = time.monotonic() + 40
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
    """Delete the function and its log group; only an already-gone resource
    (ResourceNotFoundException) is tolerated."""
    for delete in (
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=40):
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



def _depth(v):
    if isinstance(v, (dict, list)):
        vals = v.values() if isinstance(v, dict) else v
        return 1 + max([0] + [_depth(x) for x in vals])
    return 0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nodejs24.x function whose handler is the `digest` export of an ES module `calc.mjs` runs
    it: for nested events it returns the sha256, length and depth of the deep-sorted canonical
    JSON, values only executing the code yields; the deleted function then refuses Invoke."""
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("calc.mjs", _JS_CODE)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    create_resp = _create_function(lam,
        FunctionName=fn_name,
        Runtime="nodejs24.x",
        Handler="calc.digest",
        Role=_execution_role(ctx),
        Code={"ZipFile": buf.getvalue()},
        MemorySize=256,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda n=fn_name: _cleanup_fn(ctx, lam, n))
    assert create_resp["Handler"] == "calc.digest", f"CreateFunction echoed Handler={create_resp.get('Handler')!r}"
    _wait_active(lam, fn_name)

    payloads = (
        {"z": [3, {"y": "deep", "b": [True, None]}], "a": {"m": {"n": 1.25}}},
        [{"id": ctx.unique_name("i-"), "tags": ["x", "w"]}, 42, "tail"],
        {"only": {"one": {"path": {"down": "here"}}}},
    )
    for payload in payloads:
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        want = {"module": "esm", "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "length": len(text), "depth": _depth(payload)}
        resp = _invoke_sync(lam, fn_name, payload)
        assert resp == want, f"payload {payload!r}: expected {want!r}, got {resp!r}"

    fn_arn = create_resp["FunctionArn"]
    lam.delete_function(FunctionName=fn_name)
    # The delete is eventually consistent: read the function until it is refused.
    deadline = time.monotonic() + 40
    while True:
        try:
            last = lam.get_function(FunctionName=fn_name)["Configuration"]
        except ClientError as exc:
            _assert_not_found(exc, f"GetFunction {fn_name}", f"Function not found: {fn_arn}")
            break
        assert time.monotonic() < deadline, (
            f"GetFunction {fn_name} still answers 40s after the delete: last State {last.get('State')!r}")
        time.sleep(2)
    # On AWS Invoke keeps reaching a deleted function after GetFunction refuses it, so it is retried.
    deadline = time.monotonic() + 40
    while True:
        try:
            last = lam.invoke(FunctionName=fn_name, Payload=b"{}")
        except ClientError as exc:
            _assert_not_found(exc, f"Invoke {fn_name}", f"Function not found: {fn_arn}:$LATEST")
            break
        assert time.monotonic() < deadline, (
            f"Invoke {fn_name} still succeeds 40s after the delete: last StatusCode "
            f"{last.get('StatusCode')!r}, ExecutedVersion {last.get('ExecutedVersion')!r}")
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
