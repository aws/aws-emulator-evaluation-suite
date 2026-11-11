"""cli-apigateway-stage-access-log-missing-destination-rejected."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-apigateway-stage-access-log-missing-destination-rejected"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """An access-log destination the push role is denied logs:CreateLogGroup on is never created and
    receives nothing, while a sibling stage logging to a pre-created log group receives entries."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    region = ctx.region
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Generated before the account role so the role's Deny can be scoped to this exact ARN.
    bad_log_group = ctx.unique_name("sim2real-behav-accesslog-bad-")
    bad_log_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{bad_log_group}"

    _ensure_apigw_account_cw_role(ctx, denied_log_group_arn=bad_log_arn)

    api_name = ctx.unique_name("sim2real-behav-api-")
    api = _run_aws(
        ctx, "apigateway", "create-rest-api", "--name", api_name,
        "--tags", f"sim2real:managed=true,sim2real={CHECK}",
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "apigateway", "delete-rest-api", "--rest-api-id", api_id, check=False))

    resources = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)
    root_id = [r["id"] for r in resources["items"] if r["path"] == "/"][0]
    resource = _run_aws(
        ctx, "apigateway", "create-resource",
        "--rest-api-id", api_id, "--parent-id", root_id, "--path-part", "ping",
    )
    resource_id = resource["id"]
    _run_aws(
        ctx, "apigateway", "put-method",
        "--rest-api-id", api_id, "--resource-id", resource_id,
        "--http-method", "GET", "--authorization-type", "NONE",
    )
    _run_aws(
        ctx, "apigateway", "put-integration",
        "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET",
        "--type", "MOCK", "--request-templates", json.dumps({"application/json": '{"statusCode": 200}'}),
    )
    _run_aws(
        ctx, "apigateway", "put-method-response",
        "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET", "--status-code", "200",
    )
    _run_aws(
        ctx, "apigateway", "put-integration-response",
        "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET",
        "--status-code", "200", "--selection-pattern", "",
    )

    dep = _run_aws(ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "good")
    deployment_id = dep["id"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "apigateway", "delete-stage", "--rest-api-id", api_id, "--stage-name", "good", check=False))
    _run_aws(
        ctx, "apigateway", "create-stage",
        "--rest-api-id", api_id, "--stage-name", "bad", "--deployment-id", deployment_id,
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "apigateway", "delete-stage", "--rest-api-id", api_id, "--stage-name", "bad", check=False))

    good_log_group = ctx.unique_name("sim2real-behav-accesslog-good-")
    _run_aws(
        ctx, "logs", "create-log-group", "--log-group-name", good_log_group,
        "--tags", f"sim2real:managed=true,sim2real={CHECK}",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "logs", "delete-log-group", "--log-group-name", good_log_group, check=False))
    good_log_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{good_log_group}"
    _run_aws(
        ctx, "apigateway", "update-stage",
        "--rest-api-id", api_id, "--stage-name", "good",
        "--patch-operations", json.dumps([
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": good_log_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": "$context.requestId $context.status"},
        ]),
    )

    # This log group is intentionally never created; the account role's Deny (above) blocks it.
    _run_aws(
        ctx, "apigateway", "update-stage",
        "--rest-api-id", api_id, "--stage-name", "bad",
        "--patch-operations", json.dumps([
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": bad_log_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": "$context.requestId $context.status"},
        ]),
    )

    good_url = f"{ctx.rest_api_url(api_id, 'good')}/ping"
    bad_url = f"{ctx.rest_api_url(api_id, 'bad')}/ping"
    good_status = _http_get_with_retries(good_url, retries=6, delay_s=4.0)
    _http_get_with_retries(bad_url, retries=2, delay_s=2.0)
    assert good_status == 200, f"expected 200 from good stage MOCK integration, got {good_status}"

    # POSITIVE CONTROL: the real, pre-created destination eventually receives access log entries.
    # Access-log delivery setup can take a couple of minutes after the account CloudWatch role is
    # attached/updated, so keep re-issuing requests while polling rather than relying on the
    # handful of initial hits above landing after the pipeline is warm. Kept to 130s (not the
    # 180s a standalone budget would allow) because the CloudWatch role's own propagation retry
    # above can itself consume up to 100s of the harness's 300s hard check-timeout wall clock.
    delivered = _poll_for_log_events(ctx, good_log_group, timeout_s=130.0, retry_url=good_url)

    # NEGATIVE: the nonexistent destination is never materialized and receives nothing — this is
    # the core permission-boundary assertion and does not depend on how fast CloudWatch happens to
    # start delivering to the (separately verified reachable, status==200) positive-control stage.
    still_missing = _poll_for_log_group_absent(ctx, bad_log_group, timeout_s=15.0)
    assert still_missing, f"log group {bad_log_group} unexpectedly came into existence"

    if not delivered:
        # The MOCK integration itself is confirmed healthy (asserted status==200 above) and the
        # stage's accessLogSettings were accepted by UpdateStage without error — this is AWS's own
        # eventual-consistency window for first-time CloudWatch access-log delivery on a brand-new
        # log group/role pairing, which can exceed this harness's fixed per-check wall-clock budget.
        raise AssertionError(
            f"access log entries never landed in {good_log_group} within the harness's check "
            "budget (CloudWatch access-log delivery can take longer than 300s on first use); "
            "negative-wiring assertion (missing destination) still passed above"
        )



def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env,
        capture_output=True, text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _ensure_apigw_account_cw_role(ctx, denied_log_group_arn: str) -> None:
    """Provision the API Gateway account-level CloudWatch push role ourselves: the full push
    permission set UpdateAccount's own validation requires -- UpdateAccount
    rejects a role missing any of it outright with BadRequestException ("does not have required
    permissions configured"), so omitting logs:CreateLogGroup account-wide is not a viable
    negative -- plus an explicit per-resource Deny on logs:CreateLogGroup scoped to
    `denied_log_group_arn`. IAM Deny always wins over Allow, so that one destination can never be
    materialized while every other log group (including the positive control's pre-created one)
    is unaffected. Always swaps in our own role (never adopts whatever cloudwatchRoleArn the
    account already has, since we need to control its exact permission set) and registers cleanup
    to restore the prior setting."""
    acct = _run_aws(ctx, "apigateway", "get-account")
    previous = acct.get("cloudwatchRoleArn") or ""

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-agwcw-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    policy_name = "apigw-push-cwl-deny-one-create"
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BroadAllow",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                        "logs:GetLogEvents",
                        "logs:FilterLogEvents",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyCreateForOneLogGroup",
                    "Effect": "Deny",
                    "Action": "logs:CreateLogGroup",
                    "Resource": [denied_log_group_arn, f"{denied_log_group_arn}:*"],
                },
            ],
        }),
    )

    def _restore_account():
        _run_aws(
            ctx, "apigateway", "update-account",
            "--patch-operations", json.dumps([{"op": "replace", "path": "/cloudwatchRoleArn", "value": previous}]),
        )

    def _delete_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    ctx.on_cleanup(_restore_account)

    # UpdateAccount itself rejects the new role until IAM has propagated its trust policy far
    # enough for API Gateway's validation to see it -- retry the actual consumer of that
    # propagation instead of sleeping blind, bounded so a genuinely stuck propagation fails loudly.
    # Measured on real AWS to sometimes exceed 60s on a freshly created role, and UpdateAccount's
    # own per-account throttle (this is an account-global singleton other checks also mutate) can
    # answer TooManyRequestsException well before propagation finishes -- back off increasingly
    # rather than hammering it at a fixed interval.
    deadline = time.monotonic() + 100.0
    last_stderr = ""
    backoff = 4.0
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx, [
                "aws", "--output", "json", "apigateway", "update-account",
                "--patch-operations", json.dumps([{"op": "replace", "path": "/cloudwatchRoleArn", "value": role["Arn"]}]),
            ],
            check=False,
        )
        if proc.returncode == 0:
            return
        last_stderr = proc.stderr[-300:]
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 12.0)
    raise AssertionError(
        f"apigateway update-account never accepted CloudWatch role {role['Arn']} within 100s "
        f"(last stderr: {last_stderr!r})"
    )


def _http_get_with_retries(url, retries=8, delay_s=5.0, timeout_s=15.0):
    last_exc = None
    for _ in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=timeout_s) as resp:
                resp.read()
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except urllib.error.URLError as e:
            last_exc = e
            time.sleep(delay_s)
    raise AssertionError(f"could not reach {url}: {last_exc}")


def _http_hit(url, timeout_s=15.0) -> int | None:
    """One traffic-generating GET; the HTTP status, or None when the host was unreachable."""
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def _poll_for_log_events(ctx, log_group_name, timeout_s=150.0, retry_url=None):
    deadline = time.monotonic() + min(timeout_s, ctx.time_left())
    last_hit = time.monotonic()
    while time.monotonic() < deadline:
        result = _run_aws(
            ctx, "logs", "filter-log-events", "--log-group-name", log_group_name, check=False,
        )
        if isinstance(result, dict) and result.get("events"):
            return True
        if retry_url is not None and time.monotonic() - last_hit > 15.0:
            _http_hit(retry_url)
            last_hit = time.monotonic()
        time.sleep(2)
    return False


def _poll_for_log_group_absent(ctx, log_group_name, timeout_s=60.0):
    assert ctx.time_left() >= timeout_s, "no budget left for the absence window"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = _run_aws(ctx, "logs", "describe-log-groups", "--log-group-name-prefix", log_group_name)
        if result.get("logGroups"):
            return False
        time.sleep(2)
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
