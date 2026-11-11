"""target-5xx-rate-alarm-config-echoes-and-its-math-separates-a-low-error-rate-from-all-errors."""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-5xx-rate-alarm-config-echoes-and-its-math-separates-a-low-error-rate-from-all-errors"
GROUP = "alb-metrics"
SERVICES = ["cloudwatch", "elbv2", "s3"]
_RUN_HEADER = "X-Sim2real-Run"
#: An ALB takes ~100 s to leave `provisioning`. Declared > 300 s so the suite budget lifts to
#: 1800 s; it is a ceiling to FAIL at, never an asserted latency.
_ACTIVE_DEADLINE_S = 420
_NS = "AWS/ApplicationELB"

#: POST /jobInstance/updateStatus and /health answer 200 "ok"; any other route answers 500.
_HANDLER_SRC = """
def handler(event, context):
    method, path = event.get("httpMethod"), event.get("path")
    if path == "/health":
        return {"statusCode": 200, "body": "ok"}
    if method == "POST" and path == "/jobInstance/updateStatus":
        return {"statusCode": 200, "body": "ok"}
    return {"statusCode": 500, "body": "Not Found"}
"""

@tags("axis:happy-path", "concern:metrics", "concern:data-plane", "plane:data", "dp:endpoint")
def run(ctx) -> None:
    """A Target_5XX count alarm and a metric-math alarm on 100*FILL(m1,0)/m2 above 50 echo their
    60 s configuration, the ALB answers each route's status, and the alarm's own expression computes
    10 for one 500 in ten requests, 100 when all answer 500, and 0 for a minute with no 500.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html
    """
    cw = ctx.client("cloudwatch")
    tok = ctx.unique_name("sim2real-alb-")
    run_id = ctx.unique_name("sim2real-run-")
    backend = _lambda_backend(ctx, tok, _HANDLER_SRC)
    alb = _new_alb(ctx, tok)
    _route(ctx, alb, backend["tg"], run_id)
    _serving(ctx, alb, run_id)
    dims = [{"Name": "LoadBalancer", "Value": alb["dim"]},
            {"Name": "TargetGroup", "Value": backend["tg_dim"]}]
    count_alarm, rate_alarm = f"{tok}-target-5xx-count", f"{tok}-target-5xx-rate"
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[count_alarm, rate_alarm]))
    cw.put_metric_alarm(AlarmName=count_alarm, Namespace=_NS, MetricName="HTTPCode_Target_5XX_Count",
                        Dimensions=dims, Statistic="Sum", Period=60, EvaluationPeriods=1,
                        DatapointsToAlarm=1, Threshold=0, ComparisonOperator="GreaterThanThreshold",
                        TreatMissingData="notBreaching")

    def stat(mid, namespace, name, metric_dims):
        return {"Id": mid, "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": name, "Dimensions": metric_dims},
            "Period": 60, "Stat": "Sum"}}

    expression = {"Id": "rate", "Expression": "100 * FILL(m1, 0) / m2",
                  "Label": "Target 5XX rate", "ReturnData": True}
    cw.put_metric_alarm(AlarmName=rate_alarm, EvaluationPeriods=1, DatapointsToAlarm=1,
                        Threshold=50, ComparisonOperator="GreaterThanThreshold",
                        TreatMissingData="notBreaching", Metrics=[
                            stat("m1", _NS, "HTTPCode_Target_5XX_Count", dims),
                            stat("m2", _NS, "RequestCount", dims), expression])

    alarms = {a["AlarmName"]: a for a in cw.describe_alarms(
        AlarmNames=[count_alarm, rate_alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"]}
    assert sorted(alarms) == sorted([count_alarm, rate_alarm]), f"described {sorted(alarms)!r}"
    count = alarms[count_alarm]
    got = {k: count.get(k) for k in ("Namespace", "MetricName", "Statistic", "Period",
                                     "EvaluationPeriods", "DatapointsToAlarm", "Threshold",
                                     "ComparisonOperator", "TreatMissingData")}
    assert got == {"Namespace": _NS, "MetricName": "HTTPCode_Target_5XX_Count", "Statistic": "Sum",
                   "Period": 60, "EvaluationPeriods": 1, "DatapointsToAlarm": 1, "Threshold": 0.0,
                   "ComparisonOperator": "GreaterThanThreshold",
                   "TreatMissingData": "notBreaching"}, f"the count alarm reads {got!r}"
    rate = alarms[rate_alarm]
    got = {k: rate.get(k) for k in ("EvaluationPeriods", "DatapointsToAlarm", "Threshold",
                                    "ComparisonOperator", "TreatMissingData")}
    assert got == {"EvaluationPeriods": 1, "DatapointsToAlarm": 1, "Threshold": 50.0,
                   "ComparisonOperator": "GreaterThanThreshold",
                   "TreatMissingData": "notBreaching"}, f"the rate alarm reads {got!r}"
    shape = [(m["Id"], m.get("Expression"), (m.get("MetricStat") or {}).get("Period"),
              (m.get("MetricStat") or {}).get("Stat"),
              ((m.get("MetricStat") or {}).get("Metric") or {}).get("MetricName"))
             for m in rate["Metrics"]]
    assert shape == [("m1", None, 60, "Sum", "HTTPCode_Target_5XX_Count"),
                     ("m2", None, 60, "Sum", "RequestCount"),
                     ("rate", "100 * FILL(m1, 0) / m2", None, None, None)], (
        f"the rate alarm's Metrics read {shape!r}")

    ok, bad = ("/jobInstance/updateStatus", 200), ("/jobInstance/", 500)
    for path, status in [ok] * 5 + [bad] + [ok] * 4 + [bad] * 6:
        got_status = _call(ctx, alb, "POST", path, run_id)[0]
        assert got_status == status, f"POST {path} answered {got_status!r}, expected {status}"

    # The same expression over counts this check publishes with explicit minutes: one 500 in ten
    # requests, six 500s in six, and ten requests with no 500 at all.
    namespace = ctx.unique_name("Sim2Real/Target5xx/")
    mine = [{"Name": "Run", "Value": run_id}]
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=10)
    low, high, clean = base, base + timedelta(minutes=1), base + timedelta(minutes=2)
    data = [("HTTPCode_Target_5XX_Count", low, 1.0), ("RequestCount", low, 10.0),
            ("HTTPCode_Target_5XX_Count", high, 6.0), ("RequestCount", high, 6.0),
            ("RequestCount", clean, 10.0)]
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": name, "Dimensions": mine, "Timestamp": ts, "Value": value, "Unit": "Count"}
        for name, ts, value in data])
    queries = [stat("m1", namespace, "HTTPCode_Target_5XX_Count", mine),
               stat("m2", namespace, "RequestCount", mine), expression]

    def computed():
        res = cw.get_metric_data(MetricDataQueries=queries, StartTime=base - timedelta(minutes=1),
                                 EndTime=base + timedelta(minutes=4), ScanBy="TimestampAscending")
        series = {r["Id"]: r for r in res["MetricDataResults"]}
        return dict(zip(series["rate"]["Timestamps"], series["rate"]["Values"]))

    values = _poll(computed, lambda v: len(v) >= 3, timeout_s=120, interval_s=5,
                   description="the rate expression over the three published minutes")
    assert values == {low: 10.0, high: 100.0, clean: 0.0}, (
        f"100 * FILL(m1, 0) / m2 should read 10 (1 of 10), 100 (6 of 6) and 0 (no 500) over the "
        f"three minutes, got {values!r}")
    assert values[low] < rate["Threshold"] < values[high], (
        f"one 500 in ten must sit under the rate threshold {rate['Threshold']} and all 500s above "
        f"it: {values!r}")


def _poll(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll probe() until predicate holds; fail naming the last observation at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


_TAGS = [{"Key": "sim2real", "Value": "api-and-observability"},
         {"Key": "sim2real:managed", "Value": "true"}]


def _new_alb(ctx, tok: str) -> dict:
    """An internet-facing ALB in the run's network behind a minted security group admitting only
    the runner on port 80. The group's delete is registered first, so LIFO removes the ALB first."""
    ec2, elb = ctx.client("ec2"), ctx.client("elbv2")
    net = ctx.network()
    subnets = net.subnet_ids[:2]
    assert len(subnets) == 2, f"the run's network has subnets {net.subnet_ids!r}; an ALB needs two AZs"
    sg = ec2.create_security_group(
        GroupName=tok, Description="sim2real ALB 5xx diagnosis", VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}])["GroupId"]
    ctx.on_cleanup(lambda: _drop_sg(ec2, sg))
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    lb = elb.create_load_balancer(Name=tok, Subnets=subnets, SecurityGroups=[sg],
                                  Scheme="internet-facing", Type="application",
                                  Tags=list(_TAGS))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _drop_alb(elb, arn))
    return {"arn": arn, "dns": lb["DNSName"], "name": tok,
            "dim": arn.split(":loadbalancer/", 1)[1]}


def _drop_alb(elb, arn: str) -> None:
    """Delete the listeners first (a target group stays in use while one points at it), then the
    load balancer, and wait until it is no longer described; a delete that never lands raises."""
    try:
        for listener in elb.describe_listeners(LoadBalancerArn=arn)["Listeners"]:
            elb.delete_listener(ListenerArn=listener["ListenerArn"])
        elb.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            elb.describe_load_balancers(LoadBalancerArns=[arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"load balancer {arn} still described 300s after its delete")


def _drop_sg(ec2, sg: str) -> None:
    deadline = time.monotonic() + 300
    while True:
        try:
            ec2.delete_security_group(GroupId=sg)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(10)  # the deleted ALB's network interfaces are released asynchronously


def _lambda_backend(ctx, tok: str, source: str) -> dict:
    """A Lambda target group whose function runs ``source``; created BEFORE the ALB, so LIFO
    deletes the ALB and its listener first. The role carries no policy, so the function never
    creates a log group."""
    iam, lam, elb = ctx.client("iam"), ctx.client("lambda"), ctx.client("elbv2")
    role = iam.create_role(RoleName=tok, Tags=list(_TAGS), AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                                                "Principal": {"Service": "lambda.amazonaws.com"},
                                                "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=tok))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    deadline = time.monotonic() + 120
    while True:
        try:
            fn = lam.create_function(FunctionName=tok, Runtime="python3.12", Role=role,
                                     Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                                     Timeout=10, MemorySize=128, Tags=dict(
                                         (t["Key"], t["Value"]) for t in _TAGS))["FunctionArn"]
            break
        except ClientError as exc:
            # a fresh role is not assumable by Lambda for a few seconds: retry that refusal only
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=tok))
    state = _poll(lambda: lam.get_function_configuration(FunctionName=tok)["State"],
                  lambda s: s in ("Active", "Failed"), timeout_s=120,
                  description=f"function {tok} leaving Pending")
    assert state == "Active", f"function {tok} reached {state!r}, not Active"
    health = {"HealthCheckEnabled": True, "HealthCheckPath": "/health",
              "HealthCheckIntervalSeconds": 35, "HealthyThresholdCount": 2,
              "UnhealthyThresholdCount": 2}
    tg = elb.create_target_group(Name=tok, TargetType="lambda", Tags=list(_TAGS), **health)
    tg_arn = tg["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _drop_tg(elb, tg_arn))
    lam.add_permission(FunctionName=tok, StatementId="alb-invoke", Action="lambda:InvokeFunction",
                       Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn)
    deadline = time.monotonic() + 120
    while True:
        try:
            elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn}])
            break
        except ClientError as exc:
            # the resource policy just granted is read eventually-consistently: retry that only
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    return {"fn": fn, "name": tok, "tg": tg_arn, "tg_dim": tg_arn.split(":")[-1]}


def _drop_tg(elb, arn: str) -> None:
    deadline = time.monotonic() + 300
    while True:
        try:
            elb.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _route(ctx, alb: dict, tg_arn: str, run_id: str) -> None:
    """Listener :80 whose default is a fixed 404 and whose one rule (priority 10) forwards only
    requests carrying this run's header, so every target-side status and metric is this check's."""
    elb = ctx.client("elbv2")
    listener = elb.create_listener(
        LoadBalancerArn=alb["arn"], Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "404", "ContentType": "text/plain", "MessageBody": "no route"}}])
    alb["listener"] = listener["Listeners"][0]["ListenerArn"]
    elb.create_rule(ListenerArn=alb["listener"], Priority=10,
                    Conditions=[{"Field": "http-header", "HttpHeaderConfig": {
                        "HttpHeaderName": _RUN_HEADER, "Values": [run_id]}}],
                    Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}])


def _call(ctx, alb: dict, method: str, path: str, run_id: str, agent: str | None = None):
    """One request to the ALB's published DNS name through ctx.endpoint_route; (status, body),
    0 when nothing answered."""
    url, route = ctx.endpoint_route(f"http://{alb['dns']}{path}")
    data = b"" if method == "POST" else None
    headers = {_RUN_HEADER: run_id, "User-Agent": agent or run_id, **route}
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except (urllib.error.URLError, OSError):
        return 0, ""


def _serving(ctx, alb: dict, run_id: str) -> None:
    """Poll the ALB to `active`, then until a routed GET /health answers 200."""
    elb = ctx.client("elbv2")
    state = _poll(lambda: elb.describe_load_balancers(LoadBalancerArns=[alb["arn"]])
                  ["LoadBalancers"][0]["State"]["Code"],
                  lambda s: s in ("active", "failed"), timeout_s=_ACTIVE_DEADLINE_S, interval_s=5,
                  description=f"ALB {alb['name']} leaving provisioning")
    assert state == "active", f"ALB {alb['name']} reached {state!r}, not active"
    _poll(lambda: _call(ctx, alb, "GET", "/health", run_id, agent=run_id + "-warmup"),
          lambda r: r[0] == 200, timeout_s=180, interval_s=5,
          description=f"a routed GET /health through {alb['dns']!r} answering 200")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
