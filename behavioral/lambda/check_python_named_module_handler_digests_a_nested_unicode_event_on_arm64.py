"""python-named-module-handler-digests-a-nested-unicode-event-on-arm64."""

from __future__ import annotations

import hashlib
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "python-named-module-handler-digests-a-nested-unicode-event-on-arm64"
GROUP = 'compute'
SERVICES = ['lambda']
#: The default service-class budget for a poll; the harness deadline bounds the run.
POLL_BUDGET_S = 40
_MODULE = "digest_app"
_FUNCTION = "summarize"

_CODE = """\
import hashlib, json


def _leaves(value):
    if isinstance(value, dict):
        return [leaf for v in value.values() for leaf in _leaves(v)]
    if isinstance(value, list):
        return [leaf for v in value for leaf in _leaves(v)]
    return [value]


def summarize(event, context):
    canonical = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    leaves = _leaves(event)
    numbers = [v for v in leaves if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return {
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "utf8_bytes": len(canonical.encode("utf-8")),
        "leaves": len(leaves),
        "number_sum": sum(numbers),
    }
"""


def _make_zip(code, filename):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


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
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = _BASIC_EXEC.format(partition=_partition(ctx))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
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


def _teardown(undo, *not_found):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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


def _wait_active(lam, fn, timeout_s=POLL_BUDGET_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    return json.loads(body) if body else None


def _leaves(value):
    if isinstance(value, dict):
        return [leaf for v in value.values() for leaf in _leaves(v)]
    if isinstance(value, list):
        return [leaf for v in value for leaf in _leaves(v)]
    return [value]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An arm64 python3.13 function whose handler is a named function in a named module digests
    nested, non-ASCII events: sha256 and UTF-8 length of the canonical JSON, leaf count and number
    sum match values computed here, and the deleted function is not found and refuses Invoke."""
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=fn,
        Runtime="python3.13",
        Handler=f"{_MODULE}.{_FUNCTION}",
        Role=_execution_role(ctx),
        Code={"ZipFile": _make_zip(_CODE, f"{_MODULE}.py")},
        Architectures=["arm64"],
        MemorySize=192,
        Timeout=20,
        Tags={"sim2real:managed": "true"},
    )
    logs = ctx.client("logs")
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn}"),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    conf = _wait_active(lam, fn)
    assert conf["Architectures"] == ["arm64"], f"expected Architectures ['arm64'], got {conf['Architectures']!r}"
    assert conf["Handler"] == f"{_MODULE}.{_FUNCTION}", f"Handler read back as {conf['Handler']!r}"

    payloads = (
        {"città": "Zürich", "emoji": "☃❤", "nested": {"list": [3, 1.5, -2], "flag": True,
                                                                  "none": None}},
        {"Ω": [{"k": ctx.unique_name("v-")}, {"k": "日本語"}], "n": 10 ** 12, "deep": {"a": {"b": {"c": 7}}}},
    )
    for payload in payloads:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        leaves = _leaves(payload)
        want = {
            "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "utf8_bytes": len(canonical.encode("utf-8")),
            "leaves": len(leaves),
            "number_sum": sum(v for v in leaves if isinstance(v, (int, float)) and not isinstance(v, bool)),
        }
        got = _invoke_sync(lam, fn, payload)
        assert got == want, f"payload={payload!r}: expected {want!r}, got {got!r}"

    want_arn = f"arn:{_partition(ctx)}:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    assert conf["FunctionArn"] == want_arn, f"expected FunctionArn {want_arn!r}, got {conf['FunctionArn']!r}"

    lam.delete_function(FunctionName=fn)
    gone = ("ResourceNotFoundException", f"Function not found: {want_arn}")
    # The delete is eventually consistent: read the configuration until it is refused.
    deadline = time.monotonic() + 40
    while True:
        try:
            last = lam.get_function_configuration(FunctionName=fn)
        except ClientError as exc:
            got = _refusal(exc.response, 404)
            break
        assert time.monotonic() < deadline, (
            f"GetFunctionConfiguration still answers 40s after the delete: last State {last.get('State')!r}")
        time.sleep(2)
    assert got == gone, f"GetFunctionConfiguration on the deleted function: expected {gone}, got {got!r}"
    # Invoke resolves the unqualified name to $LATEST, so its not-found message names that ARN. On
    # AWS Invoke keeps reaching a deleted function after GetFunction refuses it, so it is retried.
    gone_invoke = ("ResourceNotFoundException", f"Function not found: {want_arn}:$LATEST")
    deadline = time.monotonic() + 40
    while True:
        try:
            last = lam.invoke(FunctionName=fn, Payload=b"{}")
        except ClientError as exc:
            got = _refusal(exc.response, 404)
            break
        assert time.monotonic() < deadline, (
            f"Invoke of the deleted function still succeeds 40s after the delete: last StatusCode "
            f"{last.get('StatusCode')!r}, ExecutedVersion {last.get('ExecutedVersion')!r}")
        time.sleep(5)
    assert got == gone_invoke, f"Invoke on the deleted function: expected {gone_invoke}, got {got!r}"


def _refusal(resp, status):
    """(code, message) of a refusal, after grading its HTTP status class."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx for {err.get('Code')!r}, got {got_status!r}"
    )
    return err.get("Code"), err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
