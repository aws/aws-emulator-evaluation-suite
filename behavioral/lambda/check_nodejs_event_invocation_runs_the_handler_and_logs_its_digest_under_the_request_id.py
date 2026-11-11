"""nodejs-event-invocation-runs-the-handler-and-logs-its-digest-under-the-request-id."""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-event-invocation-runs-the-handler-and-logs-its-digest-under-the-request-id"
GROUP = 'packaging'
SERVICES = ['lambda']

_JS_CODE = (
    "const crypto = require('crypto');\n"
    "exports.handler = async (event) => {\n"
    "  const canonical = JSON.stringify(event, Object.keys(event).sort());\n"
    "  const sha256 = crypto.createHash('sha256').update(canonical).digest('hex');\n"
    "  console.log(`DIGEST ${event.tag} ${sha256}`);\n"
    "  return { sha256 };\n"
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


def _digest_lines(logs, group, tag):
    """The handler's DIGEST log lines for ``tag`` as (request id, level, text) triples."""
    try:
        events = logs.filter_log_events(logGroupName=group, filterPattern=f'"DIGEST {tag}"')["events"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    out = []
    for e in events:
        fields = e["message"].rstrip("\n").split("\t")
        assert len(fields) == 4, f"console.log line is not timestamp/request id/level/text: {e['message']!r}"
        out.append(tuple(fields[1:]))
    return out


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An InvocationType=Event invoke of a Node.js function answers 202 with an empty body, and the
    handler really runs: for each of two events its console.log line, under the invoke's own request
    id at level INFO, carries the node:crypto sha256 of that event's canonical JSON."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.js", _JS_CODE)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=fn_name,
        Runtime="nodejs22.x",
        Handler="index.handler",
        Role=_execution_role(ctx),
        Code={"ZipFile": buf.getvalue()},
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda n=fn_name: _cleanup_fn(ctx, lam, n))
    _wait_active(lam, fn_name)

    sent = []
    for payload in ({"tag": ctx.unique_name("t"), "qty": 5, "sku": "B-2"},
                    {"tag": ctx.unique_name("t"), "list": [1, 2, 3], "flag": False}):
        resp = lam.invoke(FunctionName=fn_name, InvocationType="Event", Payload=json.dumps(payload).encode())
        body = resp["Payload"].read()
        assert resp["StatusCode"] == 202, f"Event invoke: expected StatusCode 202, got {resp['StatusCode']!r}"
        assert body == b"", f"Event invoke: expected an empty body, got {body[:200]!r}"
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sent.append((payload["tag"], resp["ResponseMetadata"]["RequestId"],
                     hashlib.sha256(canonical.encode()).hexdigest()))

    for tag, rid, sha in sent:
        deadline = time.monotonic() + 40
        lines = _digest_lines(logs, group, tag)
        while not lines:
            assert time.monotonic() < deadline, (
                f"event {tag}: after 40s FilterLogEvents on {group} still finds no line "
                f"'DIGEST {tag} {sha}' (last answer: {lines!r})")
            time.sleep(3)
            lines = _digest_lines(logs, group, tag)
        want = (rid, "INFO", f"DIGEST {tag} {sha}")
        # Event invokes are at-least-once, so a repeat run may log the same line again.
        assert set(lines) == {want}, f"event {tag}: expected only the log line {want!r}, got {lines!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
