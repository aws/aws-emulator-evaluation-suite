"""logs-lambda-emits-to-log-group."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


CHECK = "logs-lambda-emits-to-log-group"
GROUP = 'data-plane'
SERVICES = ['logs']

def _make_logging_lambda(ctx, marker: str) -> str:
    """Create a Lambda that prints *marker*; return its function name."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _teardown_role(rn=role_name, _iam=iam):
        for pn in _iam.list_role_policies(RoleName=rn).get("PolicyNames", []):
            _iam.delete_role_policy(RoleName=rn, PolicyName=pn)
        _iam.delete_role(RoleName=rn)

    ctx.on_cleanup(_teardown_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
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
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    code = f"def lambda_handler(event, context):\n    print({marker!r})\n    return {{'ok': True}}\n"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 60
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": zip_buf.getvalue()},
                Timeout=30,
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as exc:  # noqa: BLE001 - IAM propagation retry
            msg = str(exc)
            if "cannot be assumed" in msg or "InvalidParameterValue" in msg:
                last_err = exc
                time.sleep(3)
                continue
            raise
    else:
        raise last_err or RuntimeError(f"failed to create Lambda {fn_name}")

    ctx.on_cleanup(lambda fn=fn_name: lam.delete_function(FunctionName=fn))

    def state():
        try:
            return lam.get_function_configuration(FunctionName=fn_name).get("State")
        except Exception:  # noqa: BLE001
            return None

    _poll_until(
        state, lambda s: s == "Active", timeout_s=60, interval_s=3,
        description=f"Lambda {fn_name} Active",
    )
    return fn_name

@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda's printed marker line lands in its /aws/lambda/<fn> log group."""
    svc = ctx.client("logs")
    lam = ctx.client("lambda")
    marker = "sim2real-log-marker-" + uuid.uuid4().hex[:12]
    fn_name = _make_logging_lambda(ctx, marker)

    log_group = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=log_group))

    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
    assert resp["StatusCode"] == 200, resp["StatusCode"]

    def events():
        try:
            return svc.filter_log_events(logGroupName=log_group).get("events", [])
        except Exception:  # noqa: BLE001 - group not created until first log delivery
            return []

    # Log delivery from Lambda to CloudWatch Logs is asynchronous.
    found = _poll_until(
        events,
        lambda evs: any(marker in e.get("message", "") for e in evs),
        timeout_s=180,
        interval_s=5,
        description="Lambda log line appearing in its log group",
    )
    assert any(marker in e.get("message", "") for e in found), (
        f"marker {marker!r} not found in {log_group}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
