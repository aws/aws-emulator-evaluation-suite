"""deep-sfn-3-http-task-deauthorized-connection-rejected."""
from __future__ import annotations

import io
import json
import secrets
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-3-http-task-deauthorized-connection-rejected"
GROUP = "http-task"
SERVICES = ["events", "lambda", "stepfunctions"]

_API_KEY_HEADER = "x-sim2real-key"
_EXPECTED_ERROR = "Events.ConnectionResource.InvalidConnectionState"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deauthorizing the connection behind an HTTP Task makes the same state machine fail with
    exactly Events.ConnectionResource.InvalidConnectionState; re-authorizing with a new API key
    makes it succeed again and the endpoint sees the new key (credentials are read per execution).
    """
    events_api = ctx.client("events")
    key1 = secrets.token_urlsafe(32)
    key2 = secrets.token_urlsafe(32)
    url = _echo_endpoint(ctx, (key1, key2))
    conn_name, conn_arn = _connection(ctx, key1)
    role_arn = _sfn_role(ctx, conn_arn)
    sm_arn = _create_state_machine(ctx, role_arn, _http_definition(url, conn_arn))

    # Positive control: also proves the role works.
    _e1, first = _run_until_iam_settles(ctx, sm_arn, {"payload": {"run": 1}})
    assert first["status"] == "SUCCEEDED", (
        f"run 1 (connection AUTHORIZED) must SUCCEED; got {first['status']!r} "
        f"error={first.get('error')!r} cause={first.get('cause')!r}"
    )
    echo1 = json.loads(first["output"])["ResponseBody"]
    assert echo1.get("apiKey") == key1 and echo1.get("body") == {"run": 1}, (
        f"run 1 must reach the endpoint with key #1 and its body; endpoint echoed {echo1!r}"
    )

    events_api.deauthorize_connection(Name=conn_name)
    state = _poll_until(lambda: events_api.describe_connection(Name=conn_name)["ConnectionState"],
                        lambda s: s not in ("AUTHORIZED", "DEAUTHORIZING"), timeout_s=90,
                        description="connection leaving DEAUTHORIZING")
    assert state == "DEAUTHORIZED", f"DeauthorizeConnection must end DEAUTHORIZED, got {state!r}"
    e2, second = _start_and_wait(ctx, sm_arn, {"payload": {"run": 2}})
    assert second["status"] == "FAILED", (
        f"run 2 (connection DEAUTHORIZED) must FAIL; got {second['status']!r} "
        f"output={second.get('output')!r}"
    )
    assert second.get("error") == _EXPECTED_ERROR, (
        f"run 2's error must be exactly {_EXPECTED_ERROR!r}; got {second.get('error')!r} "
        f"cause={second.get('cause')!r}"
    )
    hist2 = _history(ctx, e2)
    types2 = [e["type"] for e in hist2]
    assert "TaskSucceeded" not in types2, (
        f"no HTTP call may succeed through a DEAUTHORIZED connection; history was {types2!r}"
    )
    failed2 = [e["taskFailedEventDetails"] for e in hist2 if e["type"] == "TaskFailed"]
    assert len(failed2) == 1 and failed2[0].get("error") == _EXPECTED_ERROR, (
        f"history must record exactly one TaskFailed with error {_EXPECTED_ERROR!r}; got {failed2!r}"
    )
    assert second.get("output") is None, f"run 2 must carry no output; got {second.get('output')!r}"

    # Succeeding with the new key shows run 2 failed only because of the connection state.
    events_api.update_connection(
        Name=conn_name, AuthorizationType="API_KEY",
        AuthParameters={"ApiKeyAuthParameters": {"ApiKeyName": _API_KEY_HEADER, "ApiKeyValue": key2}},
    )
    state = _poll_until(lambda: events_api.describe_connection(Name=conn_name)["ConnectionState"],
                        lambda s: s not in ("DEAUTHORIZED", "AUTHORIZING"), timeout_s=90,
                        description="connection re-authorizing after UpdateConnection")
    assert state == "AUTHORIZED", f"UpdateConnection must re-authorize the connection, got {state!r}"
    _e3, third = _start_and_wait(ctx, sm_arn, {"payload": {"run": 3}})
    assert third["status"] == "SUCCEEDED", (
        f"run 3 (connection re-AUTHORIZED) must SUCCEED; got {third['status']!r} "
        f"error={third.get('error')!r} cause={third.get('cause')!r}"
    )
    echo3 = json.loads(third["output"])["ResponseBody"]
    assert echo3.get("apiKey") == key2 and echo3.get("body") == {"run": 3}, (
        f"run 3 must reach the endpoint with the NEW key #2 and its body; endpoint echoed {echo3!r}"
    )


_ECHO = (
    "import base64, hmac, json, os\n"
    "def handler(event, context):\n"
    "    hdrs = {k.lower(): v for k, v in (event.get('headers') or {}).items()}\n"
    f"    got = hdrs.get('{_API_KEY_HEADER}', '').encode()\n"
    "    if not any(hmac.compare_digest(got, k.encode()) for k in json.loads(os.environ['API_KEYS'])):\n"
    "        return {'statusCode': 403, 'body': ''}\n"
    "    raw = event.get('body') or ''\n"
    "    if event.get('isBase64Encoded'):\n"
    "        raw = base64.b64decode(raw).decode()\n"
    "    try:\n"
    "        body = json.loads(raw)\n"
    "    except Exception:\n"
    "        body = {'unparsed': raw}\n"
    "    out = {'method': event.get('requestContext', {}).get('http', {}).get('method'),\n"
    f"           'apiKey': hdrs.get('{_API_KEY_HEADER}'), 'body': body}}\n"
    "    return {'statusCode': 200, 'headers': {'content-type': 'application/json'},\n"
    "            'body': json.dumps(out)}\n"
)


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _role(ctx, service, policy_doc):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn-interp-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]

    def _delete():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="inline")
        except iam.exceptions.NoSuchEntityException:
            pass
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete)
    if policy_doc is not None:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    return arn


def _echo_endpoint(ctx, api_keys) -> str:
    """A Lambda function URL that echoes a request carrying one of api_keys and answers 403 to any
    other. Its role carries NO permissions at all, so the function cannot create a CloudWatch log
    group that would outlive the check."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _role(ctx, "lambda.amazonaws.com", None)
    name = ctx.unique_name("sim2real-xsvc-sfn-interp-fn-")

    def _reap_log_group():
        # Registered BEFORE create so it runs AFTER the function's own delete.
        for _ in range(5):
            try:
                logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
                return
            except logs.exceptions.ResourceNotFoundException:
                time.sleep(2)

    ctx.on_cleanup(_reap_log_group)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", _ECHO)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="handler.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, Tags={"sim2real": CHECK},
                Environment={"Variables": {"API_KEYS": json.dumps(list(api_keys))}},
            )
            break
        except ClientError as err:
            if (err.response["Error"]["Code"] == "InvalidParameterValueException"
                    and time.monotonic() < deadline):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
                lambda s: s == "Active", timeout_s=90, description=f"function {name} Active")
    url = lam.create_function_url_config(FunctionName=name, AuthType="NONE")["FunctionUrl"]
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=name))
    lam.add_permission(FunctionName=name, StatementId="url", Action="lambda:InvokeFunctionUrl",
                       Principal="*", FunctionUrlAuthType="NONE")
    lam.add_permission(FunctionName=name, StatementId="url-invoke", Action="lambda:InvokeFunction",
                       Principal="*", InvokedViaFunctionUrl=True)
    return url


def _connection(ctx, api_key_value):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-xsvc-sfn-interp-conn-")
    arn = events.create_connection(
        Name=name, AuthorizationType="API_KEY", Description="sim2real http task check",
        AuthParameters={"ApiKeyAuthParameters": {"ApiKeyName": _API_KEY_HEADER,
                                                 "ApiKeyValue": api_key_value}},
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: events.delete_connection(Name=name))
    state = _poll_until(lambda: events.describe_connection(Name=name)["ConnectionState"],
                        lambda s: s in ("AUTHORIZED", "CREATE_FAILED"), timeout_s=90,
                        description="connection leaving CREATING")
    assert state == "AUTHORIZED", f"connection must be AUTHORIZED, got {state!r}"
    return name, arn


def _sfn_role(ctx, conn_arn):
    conn_glob = conn_arn.rsplit("/", 2)[0] + "/*"
    return _role(ctx, "states.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "states:InvokeHTTPEndpoint", "Resource": "*"},
        {"Effect": "Allow", "Action": "events:RetrieveConnectionCredentials", "Resource": conn_glob},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
         "Resource": "arn:aws:secretsmanager:*:*:secret:events!connection/*"},
    ]})


def _http_definition(url, conn_arn):
    return json.dumps({
        "StartAt": "Call",
        "States": {"Call": {
            "Type": "Task", "Resource": "arn:aws:states:::http:invoke",
            "Parameters": {
                "ApiEndpoint": url, "Method": "POST",
                "Authentication": {"ConnectionArn": conn_arn},
                "Headers": {"content-type": "application/json"},
                "RequestBody.$": "$.payload",
            },
            "End": True,
        }},
    })


def _create_state_machine(ctx, role_arn, definition):
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the fresh
    role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn-interp-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _start_and_wait(ctx, sm_arn, payload, timeout_s=120.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    desc = _poll_until(lambda: sfn.describe_execution(executionArn=exec_arn),
                       lambda d: d["status"] != "RUNNING", timeout_s=timeout_s, interval_s=1.0,
                       description=f"execution {exec_arn} leaving RUNNING")
    return exec_arn, desc


def _run_until_iam_settles(ctx, sm_arn, payload):
    """Run the execution; re-run ONLY while it fails with the access-denied error a freshly
    written role policy produces before it propagates. Any other outcome is returned as-is."""
    deadline = time.monotonic() + 120.0
    while True:
        exec_arn, desc = _start_and_wait(ctx, sm_arn, payload)
        text = f"{desc.get('error') or ''} {desc.get('cause') or ''}"
        if (desc["status"] == "FAILED" and time.monotonic() < deadline
                and ("AccessDenied" in text or "not authorized to assume" in text)):
            time.sleep(5.0)
            continue
        return exec_arn, desc


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
