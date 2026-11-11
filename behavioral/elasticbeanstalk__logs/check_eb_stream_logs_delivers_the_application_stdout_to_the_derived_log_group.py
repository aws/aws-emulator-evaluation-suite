"""eb-stream-logs-delivers-the-application-stdout-to-the-derived-log-group."""
from __future__ import annotations

import http.client
import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "eb-stream-logs-delivers-the-application-stdout-to-the-derived-log-group"
GROUP = "environment-data-plane"
SERVICES = ["elasticbeanstalk", "logs"]

#: Prefixes the failure raised when an environment is Ready but nothing answers on its CNAME.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals meaning the new IAM principal is not yet visible to Elastic Beanstalk.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: A stdlib-only application, so the bundle needs no dependency install and serves a check nonce.
#:
#: Routes:
#:   /                  -> "sim2real-nonce=<NONCE>" (200), or "degraded <NONCE>" (500) once
#:                         /sim2real/fail-on has been called
#:   /sim2real/env      -> JSON of every SIM2REAL_* variable in the process environment
#:   /sim2real/boot     -> JSON {boot, nonce, uptime_s, hits}; `boot` is minted once per PROCESS
#:                         start, so it changes on any app-server restart and `hits` resets with it
#:   /sim2real/file?<p> -> the contents of the on-instance path <p>, or 404
#:   /sim2real/log      -> writes "SIM2REAL-LOG-LINE <NONCE>" to the process stdout and echoes it
#:   /sim2real/fail-on  -> subsequent "/" requests answer 500
#:   /sim2real/fail-off -> subsequent "/" requests answer 200 again
_SERVER_PY = '''
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOOT = uuid.uuid4().hex
START = time.time()
STATE = {"fail": False, "hits": 0}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        if p == "/sim2real/env":
            self._send(200, json.dumps(
                {k: v for k, v in os.environ.items() if k.startswith("SIM2REAL_")},
                sort_keys=True))
        elif p == "/sim2real/boot":
            STATE["hits"] += 1
            self._send(200, json.dumps(
                {"boot": BOOT, "nonce": NONCE, "hits": STATE["hits"],
                 "uptime_s": round(time.time() - START, 3)}, sort_keys=True))
        elif p == "/sim2real/file":
            try:
                with open(q) as f:
                    self._send(200, f.read())
            except OSError as exc:
                self._send(404, "no-such-file " + q + ": " + str(exc))
        elif p == "/sim2real/log":
            line = "SIM2REAL-LOG-LINE " + NONCE
            sys.stdout.write(line + chr(10))
            sys.stdout.flush()
            self._send(200, line)
        elif p == "/sim2real/fail-on":
            STATE["fail"] = True
            self._send(200, "fail-on " + NONCE)
        elif p == "/sim2real/fail-off":
            STATE["fail"] = False
            self._send(200, "fail-off " + NONCE)
        elif STATE["fail"]:
            self._send(500, "degraded " + NONCE)
        else:
            self._send(200, "sim2real-nonce=" + NONCE)


ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8000"))), H).serve_forever()
'''


def _app_zip(nonce: str, extra: dict[str, str] | None = None) -> bytes:
    """A source bundle serving ``nonce``: a Procfile web command plus the stdlib server above.

    ``extra`` adds arbitrary members (a `.ebextensions/*.config`, a static asset).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Procfile", "web: python3 -u server.py\n")
        z.writestr("server.py", "NONCE = " + repr(nonce) + "\n" + _SERVER_PY)
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return buf.getvalue()


def _poll(probe, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll ``probe()`` until ``pred`` holds; raise AssertionError quoting the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last was {last!r}")
        time.sleep(interval_s)


def _describe_env(eb, env_name):
    envs = eb.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments") or []
    return envs[0] if envs else None


def _http_get(ctx, url: str, timeout: float = 20.0):
    """(status, body) for a plain HTTP GET; an HTTP error status is a result, not an exception."""
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-eb-behavioral"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _http_probe(ctx, url: str, timeout: float = 8.0):
    """(status, body) where a transport failure becomes the status ``"<no-response>"``."""
    try:
        return _http_get(ctx, url, timeout=timeout)
    except (OSError, http.client.HTTPException) as exc:
        # Narrow on purpose: only refused, reset and truncated connections count as no response.
        return "<no-response>", f"{type(exc).__name__}: {exc}"


def _http_until(ctx, url: str, pred, *, timeout_s: float, interval_s: float = 10.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds; fail if unreachable at the end."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = _http_probe(ctx, url, timeout=20.0)
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: {what} — nothing satisfying the condition came back from "
                f"{url!r} within {timeout_s}s; last outcome {last!r}. A provisioned-but-"
                f"unconnectable environment is a failure, not an environment limitation.")
        time.sleep(interval_s)


def _solution_stack(eb) -> str:
    """A current AL2023 Python solution stack, resolved from the service, never hardcoded.

    On Python the streamed /var/log/web.stdout.log carries the application's stdout.
    """
    stacks = eb.list_available_solution_stacks().get("SolutionStacks") or []
    py = [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
    assert py, (
        f"this check needs an Amazon Linux 2023 Python solution stack; "
        f"ListAvailableSolutionStacks offered none, returning {stacks[:12]!r}")
    return py[0]


def _eb_iam(ctx, marker: str, extra_instance_policies=()):
    """The instance profile + service role an environment needs, with LIFO teardown."""
    iam = ctx.client("iam")

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": marker}])
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policies:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-svc-role-")
    profile = ctx.unique_name("sim2real-eb-profile-")
    _role(ec2_role, "ec2.amazonaws.com",
          ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier", *extra_instance_policies])
    _role(svc_role, "elasticbeanstalk.amazonaws.com",
          ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
           "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"])
    iam.create_instance_profile(InstanceProfileName=profile)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile, RoleName=ec2_role))
    return profile, svc_role


def _base_options(profile, service_role, single_instance=True):
    """The minimum option set for a working environment."""
    return [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType",
         "Value": "SingleInstance" if single_instance else "LoadBalanced"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType",
         "Value": "t3.micro"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile",
         "Value": profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole",
         "Value": service_role},
        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType",
         "Value": "enhanced"},
    ]


def _create_env(ctx, eb, **kwargs):
    """CreateEnvironment with a bounded retry over the IAM-propagation refusal, + LIFO teardown.

    IAM reports no signal that a principal is usable by another service; the refusal is the signal.
    """
    env_name = kwargs["EnvironmentName"]
    create_deadline_s = 300.0
    deadline = time.monotonic() + create_deadline_s
    while True:
        try:
            resp = eb.create_environment(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            role_ish = "role" in str(exc).lower() or "permission" in str(exc).lower()
            if (code not in _IAM_PROPAGATION_CODES or not role_ish
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _terminate(eb, env_name))
    return resp


def _terminate(eb, env_name):
    """Terminate and poll to Terminated; this routinely takes several minutes."""
    terminate_deadline_s = 900.0
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the state this function wants.
        if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue", "ResourceNotFoundException"):
            raise
    _poll(lambda: (_describe_env(eb, env_name) or {}).get("Status"),
          lambda s: s is None or s == "Terminated",
          timeout_s=terminate_deadline_s, interval_s=15,
          what=f"environment {env_name} reaching Terminated")


def _publish_version(ctx, eb, s3, app, marker, nonce, extra=None, label_prefix="v-"):
    """Upload a source bundle and create a PROCESSED application version from it.

    Returns (version_label, bucket, key). The Processed wait is bounded and raises.
    """
    bucket = eb.create_storage_location()["S3Bucket"]
    label = ctx.unique_name(label_prefix)
    key = f"sim2real-eb/{app}/{label}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce, extra),
                  Tagging=f"sim2real={marker}")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    eb.create_application_version(
        ApplicationName=app, VersionLabel=label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key}, Process=True,
        Tags=[{"Key": "sim2real", "Value": marker}])
    ctx.on_cleanup(lambda: eb.delete_application_version(
        ApplicationName=app, VersionLabel=label, DeleteSourceBundle=False))
    # Case-folded: AWS answers "PROCESSED" while the API model declares "Processed".
    process_deadline_s = 300.0
    status = _poll(
        lambda: eb.describe_application_versions(
            ApplicationName=app, VersionLabels=[label])["ApplicationVersions"][0]["Status"],
        lambda s: s.upper() != "PROCESSING",
        timeout_s=process_deadline_s, interval_s=5,
        what=f"application version {label} leaving Processing")
    assert status.upper() == "PROCESSED", (
        f"version {label!r} must process cleanly before it can be deployed; "
        f"DescribeApplicationVersions reports Status={status!r}")
    return label, bucket, key


def _ready(eb, env_name, what_suffix=""):
    """Wait for the environment to settle Ready; the poll never ends on Terminated/Terminating."""
    ready_deadline_s = 1500.0
    env = _poll(lambda: _describe_env(eb, env_name),
                lambda e: e is not None and e.get("Status") == "Ready",
                timeout_s=ready_deadline_s, interval_s=20,
                what=f"environment {env_name} reaching Ready{what_suffix}")
    assert env["Status"] == "Ready", (
        f"settled Status must be exactly Ready, got {env['Status']!r}")
    return env


def _new_application(ctx, eb, prefix, marker):
    """Create the application, registering its delete first so LIFO teardown runs it last,
    after every environment terminate."""
    app = ctx.unique_name(prefix)
    eb.create_application(ApplicationName=app, Tags=[{"Key": "sim2real", "Value": marker}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    return app



@tags("axis:happy-path", "cap:c3", "concern:metrics", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StreamLogs delivers the app's stdout to the log group derived from the on-instance path,
    applies RetentionInDays, and creates no group for a file the platform does not stream.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.cloudwatchlogs.html
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")
    marker = "eb-stream-logs"
    nonce = ctx.unique_name("nonce-")
    log_ns = "aws:elasticbeanstalk:cloudwatch:logs"

    app = _new_application(ctx, eb, "sim2real-eb-log-app-", marker)
    label, _bucket, _key = _publish_version(ctx, eb, s3, app, marker, nonce)

    env = ctx.unique_name("sim2real-eb-log-env-")
    profile, role = _eb_iam(ctx, marker)
    # Documented rule: the group name is /aws/elasticbeanstalk/<env> plus the on-instance path.
    group_prefix = f"/aws/elasticbeanstalk/{env}"
    stdout_group = f"{group_prefix}/var/log/web.stdout.log"
    # A path the per-platform table lists for Ruby only, so a Python environment never streams it.
    ruby_only_group = f"{group_prefix}/var/log/puma/puma.log"
    retention_days = 1

    _create_env(
        ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
        CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
        OptionSettings=_base_options(profile, role) + [
            {"Namespace": log_ns, "OptionName": "StreamLogs", "Value": "true"},
            {"Namespace": log_ns, "OptionName": "DeleteOnTerminate", "Value": "true"},
            {"Namespace": log_ns, "OptionName": "RetentionInDays",
             "Value": str(retention_days)},
        ],
        Tags=[{"Key": "sim2real", "Value": marker}])

    def _drop_group(name):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            # DeleteOnTerminate=true means Beanstalk may already have removed it.
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(lambda: _drop_group(stdout_group))
    ready = _ready(eb, env)
    url = f"http://{ready['CNAME']}/"
    _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1], timeout_s=600.0, interval_s=10,
                what=f"{env} serving its own nonce before its logs are examined")

    def _groups():
        found = {}
        token = None
        while True:
            kwargs = {"logGroupNamePrefix": group_prefix}
            if token:
                kwargs["nextToken"] = token
            page = logs.describe_log_groups(**kwargs)
            for g in page.get("logGroups") or []:
                found[g["logGroupName"]] = g
            token = page.get("nextToken")
            if not token:
                return found

    # The group exists at the derived name.
    groups = _poll(_groups, lambda d: stdout_group in d, timeout_s=600.0, interval_s=15,
                   what=(f"CloudWatch Logs holding the group {stdout_group!r}, derived by "
                         f"prefixing the on-instance path with /aws/elasticbeanstalk/{env}"))
    assert stdout_group in groups, (
        f"StreamLogs=true must create the log group whose name is the documented prefix plus the "
        f"on-instance path; expected {stdout_group!r} among {sorted(groups)!r}")

    # RetentionInDays reached the log group.
    assert groups[stdout_group].get("retentionInDays") == retention_days, (
        f"the RetentionInDays option must configure the CloudWatch Logs group itself; the group "
        f"{stdout_group!r} reports retentionInDays "
        f"{groups[stdout_group].get('retentionInDays')!r}, expected {retention_days}")

    real_instances = {
        i["Id"] for i in
        eb.describe_environment_resources(EnvironmentName=env)["EnvironmentResources"]["Instances"]
    }
    assert real_instances, "a Ready environment serving HTTP must report at least one instance"

    # No group exists for a log file this platform does not stream.
    ruby = logs.describe_log_groups(
        logGroupNamePrefix=ruby_only_group).get("logGroups", [])
    assert ruby == [], (
        f"the streamed log set is decided by the platform: a Python environment must NOT have a "
        f"group for the Ruby-only {ruby_only_group!r}, but describe_log_groups returned {ruby!r}. "
        f"A backend that materialises a group for any name asked about fails here")

    # The application's own stdout line arrives.
    expected_line = f"SIM2REAL-LOG-LINE {nonce}"
    before_ms = int(time.time() * 1000)
    logged = _http_get(ctx, f"{url}sim2real/log")
    assert logged[0] == 200 and logged[1].strip() == expected_line, (
        f"the application must confirm it wrote the line to its own stdout; the route returned "
        f"{logged!r}, expected 200 and {expected_line!r}")

    def _events():
        return logs.filter_log_events(
            logGroupName=stdout_group, startTime=before_ms - 60_000,
            filterPattern=f'"{nonce}"').get("events") or []

    events = _poll(_events, lambda evs: bool(evs), timeout_s=600.0, interval_s=15,
                   what=(f"the line the application printed to stdout arriving in "
                         f"{stdout_group!r}"))
    hits = [e for e in events if expected_line in (e.get("message") or "")]
    assert hits, (
        f"the delivered log events must contain the exact line the application printed; expected "
        f"{expected_line!r} among {[e.get('message') for e in events][:5]!r}")

    # The event cannot predate the request that caused it nor postdate the read (with skew).
    after_ms = int(time.time() * 1000)
    skew_ms = 60_000
    for hit in hits:
        ts = hit.get("timestamp")
        assert ts is not None, f"a delivered event must carry a timestamp; got {hit!r}"
        assert before_ms - skew_ms <= ts <= after_ms + skew_ms, (
            f"the event's timestamp {ts} must fall in the window in which this check caused it: "
            f"[{before_ms - skew_ms}, {after_ms + skew_ms}] (event {hit!r})")

    # A stream in the group must be attributable to one of the environment's instances.
    streams = logs.describe_log_streams(logGroupName=stdout_group).get("logStreams") or []
    names = [s.get("logStreamName") or "" for s in streams]
    assert names, (
        f"the group {stdout_group!r} must contain at least one log stream once an event has been "
        f"delivered to it; describe_log_streams returned {streams!r}")
    assert any(any(iid in name for iid in real_instances) for name in names), (
        f"a delivered stream must be attributable to one of the environment's real instances "
        f"{sorted(real_instances)!r}; the group's streams are {names!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
