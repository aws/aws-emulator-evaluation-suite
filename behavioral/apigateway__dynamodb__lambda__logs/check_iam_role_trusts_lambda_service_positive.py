"""iam-role-trusts-lambda-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trusts-lambda-service-positive"
GROUP = "trust-policy"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_HANDLER_CODE = (
    "def handler(event, context):\n"
    "    marker = event.get('marker', 'no-marker')\n"
    "    print('MARKER::' + marker)\n"
    "    return {'marker': marker}\n"
)


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting lambda.amazonaws.com lets Lambda assume it, run, and ship logs to CloudWatch."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    role_name = ctx.unique_name("sim2real-lambda-trust-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy("lambda.amazonaws.com"),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "logs-write"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    func_name = ctx.unique_name("sim2real-lambda-trust-fn-")
    zip_bytes = _zip_bytes(_HANDLER_CODE)
    _create_function_with_retry(lam, func_name, role_arn, zip_bytes)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_function_active(lam, func_name)

    log_group = f"/aws/lambda/{func_name}"

    def _cleanup_log_group():
        try:
            logs.delete_log_group(logGroupName=log_group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_log_group)

    marker = ctx.unique_name("marker-")
    resp = _invoke_with_retry(lam, func_name, marker)
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"marker": marker}, f"expected payload {{'marker': {marker!r}}}, got {payload!r}"

    events = _poll_log_marker(logs, log_group, marker, timeout_s=90.0)
    assert events, f"expected a CloudWatch Logs event containing marker {marker!r}"
    assert any(marker in e.get("message", "") for e in events), (
        f"marker {marker!r} not found in any of the {len(events)} log event(s) read back "
        f"from {log_group!r} via filter_log_events"
    )


def _trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function_with_retry(lam, name, role_arn, zip_bytes, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                Publish=True,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "assume" in str(e).lower():
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err if last_err else RuntimeError("create_function retry timeout")


def _poll_log_marker(logs_client, log_group, marker, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs_client.filter_log_events(
                logGroupName=log_group, filterPattern=f'"{marker}"'
            )
            if resp.get("events"):
                return resp["events"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return []


def _wait_for_function_active(lam, func_name, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        conf = lam.get_function_configuration(FunctionName=func_name)
        last_state = conf.get("State")
        if last_state == "Active":
            return conf
        if last_state == "Failed":
            raise RuntimeError(f"function {func_name} entered Failed state")
        time.sleep(interval_s)
    raise RuntimeError(f"function {func_name} did not become Active (last state={last_state})")


def _invoke_with_retry(lam, func_name, marker, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.invoke(
                FunctionName=func_name,
                Payload=json.dumps({"marker": marker}).encode("utf-8"),
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceConflictException":
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise last_err if last_err else RuntimeError("invoke retry timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

