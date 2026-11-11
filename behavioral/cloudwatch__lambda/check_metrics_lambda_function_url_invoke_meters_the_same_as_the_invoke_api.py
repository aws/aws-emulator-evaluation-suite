"""metrics-lambda-function-url-invoke-meters-the-same-as-the-invoke-api."""

from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-lambda-function-url-invoke-meters-the-same-as-the-invoke-api"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_SUCCESSES = 3
_FAILS = 2
_UNSIGNED_ATTEMPTS = 2
_METRIC_BUDGET_S = 240.0
_URL_READY_BUDGET_S = 120.0
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."

_HANDLER = """
exports.handler = async (event) => {
  const qs = event.queryStringParameters || {};
  if (qs.fail === "1") {
    throw new Error("sim2real deliberate failure");
  }
  return { statusCode: 200, headers: { "content-type": "application/json" },
           body: JSON.stringify({ ok: true }) };
};
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("cap:c3", "cap:c7", "concern:metrics", "concern:negative-classes", "concern:data-plane",
      "dp:endpoint", "plane:data", "axis:rejection", "timing:real-time")
def run(ctx) -> None:
    """An unsigned request to an AWS_IAM Function URL is refused before the handler runs, so it
    never counts in AWS/Lambda Invocations, while SigV4-signed requests to the same URL meter
    Invocations/Duration/Errors exactly as the signed Invoke API would.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
    """
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    name = _function(ctx, lam, role_arn)
    url = _create_url(ctx, lam, name)

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    for _ in range(_UNSIGNED_ATTEMPTS):
        obs = _http(ctx, url)
        assert obs["status"] == 403, f"an unsigned Function URL request must be refused: {obs!r}"
        assert json.loads(obs["body"]) == {"Message": "Forbidden"}, obs

    # Every signed request is accounted for: a 200 or 502 ran the handler and is expected in the
    # metrics, and the only other answer allowed while the URL's permission propagates is a 403,
    # which, like the unsigned requests, never reaches the handler.
    ok_seen = 0
    while ok_seen < _SUCCESSES:

        def _served(o):
            assert o["status"] in (200, 403), (
                f"a signed Function URL request answered {o!r}; only 200, or 403 before the "
                f"URL's permission is in effect, keeps the metered request count known"
            )
            return o["status"] == 200

        obs = _poll_until(
            lambda: _http(ctx, url, sign=True), _served,
            timeout_s=_URL_READY_BUDGET_S, interval_s=2.0,
            description="a signed Function URL request being served",
        )
        assert json.loads(obs["body"]) == {"ok": True}, f"successful call returned {obs!r}"
        ok_seen += 1

    for _ in range(_FAILS):
        obs = _http(ctx, url, sign=True, query="fail=1")
        assert obs["status"] == 502, f"a throwing handler must answer 502, got {obs!r}"

    fn_dim = [("FunctionName", name)]
    want = {"Invocations": float(_SUCCESSES + _FAILS), "Errors": float(_FAILS)}
    want_duration_count = _SUCCESSES + _FAILS

    def _probe() -> dict:
        got = {k: _sum(cw, k, fn_dim, start) for k in want}
        got["Duration"] = _sample_count(cw, "Duration", fn_dim, start)
        return got

    seen = _poll_until(
        _probe,
        # Stop once every metric has reached its count; a metric past its count stops the poll
        # too, and the exact assertions below then fail on it.
        lambda got: (
            all(got[k] is not None and got[k] >= v for k, v in want.items())
            and got["Duration"] >= want_duration_count
        ) or any(got[k] is not None and got[k] > v for k, v in want.items()),
        timeout_s=_METRIC_BUDGET_S, interval_s=15.0,
        description=(
            f"AWS/Lambda Invocations/Errors reaching {want!r} and Duration SampleCount "
            f"reaching {want_duration_count!r}"
        ),
    )
    for metric, expected in want.items():
        assert seen[metric] == expected, (
            f"AWS/Lambda {metric} Sum for [FunctionName={name}] is {seen[metric]!r}, expected "
            f"exactly {expected!r}: {_UNSIGNED_ATTEMPTS} rejected unsigned requests, "
            f"{_SUCCESSES} signed successes and {_FAILS} signed throwing requests were made "
            f"(all read: {seen!r})"
        )

    assert seen["Duration"] == want_duration_count, (
        f"AWS/Lambda Duration SampleCount for [FunctionName={name}] is {seen['Duration']!r}, "
        f"expected exactly {want_duration_count!r}: the {_UNSIGNED_ATTEMPTS} unsigned requests "
        f"never reached the handler and must not report a duration"
    )

    throttles = _sum(cw, "Throttles", fn_dim, start) or 0.0
    assert throttles == 0.0, (
        f"AWS/Lambda Throttles Sum for [FunctionName={name}] is {throttles!r}; neither a thrown "
        f"handler error nor a rejected unsigned request is ever a Throttle"
    )


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _role(ctx) -> str:
    """An execution role with NO CloudWatch Logs permission, on purpose: the metrics under test are
    published by the Lambda service, not by the function, and a role that cannot create a log
    group means the check leaves no /aws/lambda/<fn> group behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mlfu-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-mlfu-fn-")[:64]
    logs = ctx.client("logs")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function, in case the platform
    # still manages to create a log group despite the role carrying no logs permission.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _URL_READY_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="nodejs22.x",
                Architectures=["arm64"],
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip({"index.js": _HANDLER})},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or err.get("Message") != _ROLE_NOT_READY:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateFunction {name} kept failing on role propagation: {err!r}"
                ) from exc
            time.sleep(3.0)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return name


def _create_url(ctx, lam, name: str) -> str:
    cfg = lam.create_function_url_config(FunctionName=name, AuthType="AWS_IAM")
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_url_config(FunctionName=name), "ResourceNotFoundException"))
    assert not (p := ctx.published_url_mismatch(cfg["FunctionUrl"])), p
    return cfg["FunctionUrl"]


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 4.0,
                    budget_s: float = 40.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
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


def _ssl_context(ctx) -> ssl.SSLContext:
    verify = ctx.http_verify
    if verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if isinstance(verify, str) and verify:
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _sign(ctx, method: str, url: str, headers: dict, data) -> dict:
    """SigV4 headers for a request to ``url``, signed with this check's own credentials."""
    frozen = ctx.client("lambda")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=data, headers=dict(headers))
    SigV4Auth(frozen, "lambda", ctx.region).add_auth(req)
    return dict(req.headers.items())


def _http(ctx, url: str, *, query: str | None = None, sign: bool = False,
          timeout_s: float = 40.0) -> dict:
    """One raw HTTPS GET to the published Function URL. Never raises on 4xx/5xx."""
    full = url if not query else f"{url.rstrip('/')}?{query}"
    headers = _sign(ctx, "GET", full, {}, None) if sign else {}
    target, route = ctx.endpoint_route(full)
    req = urllib.request.Request(target, method="GET", headers={**headers, **route})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(ctx))
    except urllib.error.HTTPError as exc:
        resp = exc
    with resp:
        return {
            "status": resp.status if hasattr(resp, "status") else resp.code,
            "body": resp.read(),
        }


def _series(cw, metric: str, dims: list[tuple[str, str]], start, stats: list[str]) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=stats,
    )["Datapoints"]


def _sum(cw, metric: str, dims: list[tuple[str, str]], start) -> float | None:
    dps = _series(cw, metric, dims, start, ["Sum"])
    return float(sum(d["Sum"] for d in dps)) if dps else None


def _sample_count(cw, metric: str, dims: list[tuple[str, str]], start) -> int:
    dps = _series(cw, metric, dims, start, ["SampleCount"])
    return int(sum(d["SampleCount"] for d in dps))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
