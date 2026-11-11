"""eb-enhanced-health-degrades-when-the-application-returns-http-500."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags  # noqa: F401


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)



CHECK = "eb-enhanced-health-degrades-when-the-application-returns-http-500"
GROUP = 'environment-data-plane'
SERVICES = ['elasticbeanstalk']

#: Lets a Ready environment with nothing listening on the CNAME fail as a missing data plane.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The application the check deploys. stdlib only, so the bundle needs no dependency install and
#: the served bytes are decided here rather than by a platform sample app: the HTTP assertion is
#: then an identity law over a nonce this file minted, not a pinned constant.
_SERVER_PY = '''
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"fail": False}


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
        if p == "/sim2real/env":
            env = {k: v for k, v in os.environ.items() if k.startswith("SIM2REAL_")}
            self._send(200, json.dumps(env, sort_keys=True))
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


def _app_zip(nonce: str) -> bytes:
    """A source bundle serving ``nonce``: a Procfile web command plus the stdlib server above."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Procfile", "web: python3 -u server.py\n")
        z.writestr("server.py", "NONCE = " + repr(nonce) + "\n" + _SERVER_PY)
    return buf.getvalue()


def _poll(probe, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll ``probe()`` until ``pred`` holds; AssertionError quoting the last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
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


def _http_until(ctx, url: str, pred, *, timeout_s: float, interval_s: float = 2.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds.

    A connection failure after the budget is a FAILURE, never a skip: an environment the control
    plane calls Ready and nobody can reach is the defect this check exists to find.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = _http_get(ctx, url)
        except Exception as exc:  # noqa: BLE001 — a transport failure is an outcome to report
            last = ("<no-response>", f"{type(exc).__name__}: {exc}")
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: {what} — nothing satisfying the condition came back from "
                f"{url!r} within {timeout_s}s; last outcome {last!r}. A provisioned-but-"
                f"unconnectable environment is a failure, not an environment limitation.")
        time.sleep(interval_s)


def _solution_stack(eb) -> str:
    """A current AL2023 Python solution stack, resolved from the service, never hardcoded."""
    stacks = eb.list_available_solution_stacks().get("SolutionStacks") or []
    py = [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
    assert py, f"no AL2023 Python solution stack offered; got {stacks[:12]!r}"
    return py[0]


def _eb_iam(ctx):
    """The instance profile + service role an environment needs, with LIFO teardown.

    Returns (instance_profile|None, service_role|None); (None, None) when IAM is unreachable, so a
    target that serves no IAM still exercises the Beanstalk path with the service's own defaults.
    """
    iam = ctx.client("iam")
    try:
        iam.list_roles(MaxItems=1)
    except Exception:  # noqa: BLE001 — no IAM at all: let EB apply its defaults
        return None, None

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": "eb-health-5xx"}])
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policies:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-svc-role-")
    profile = ctx.unique_name("sim2real-eb-profile-")
    _role(ec2_role, "ec2.amazonaws.com",
          ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"])
    _role(svc_role, "elasticbeanstalk.amazonaws.com",
          ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
           "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"])
    iam.create_instance_profile(InstanceProfileName=profile)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile, RoleName=ec2_role))
    # IAM exposes no condition that reports a principal has become usable by another service, so
    # there is nothing to poll here; the bounded CreateEnvironment retry below is what makes this
    # correct — it absorbs the propagation delay itself rather than a flat pre-sleep guessing it.
    return profile, svc_role


def _base_options(profile, service_role):
    opts = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType",
         "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType",
         "Value": "t3.micro"},
    ]
    if profile:
        opts.append({"Namespace": "aws:autoscaling:launchconfiguration",
                     "OptionName": "IamInstanceProfile", "Value": profile})
    if service_role:
        opts += [
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole",
             "Value": service_role},
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system",
             "OptionName": "SystemType", "Value": "enhanced"},
        ]
    return opts


def _create_env(ctx, eb, **kwargs):
    """CreateEnvironment with a bounded retry over the IAM-propagation refusal, + LIFO teardown."""
    env_name = kwargs["EnvironmentName"]
    deadline = time.monotonic() + 300
    while True:
        try:
            resp = eb.create_environment(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if time.monotonic() >= deadline or not (
                    "not have permission" in msg or "cannot be assumed" in msg
                    or "InvalidParameterValue" in msg and "role" in msg.lower()):
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _terminate(eb, env_name))
    return resp


def _terminate(eb, env_name):
    """Terminate and poll to Terminated (routinely 180-420 s on AWS)."""
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the wanted state; anything else re-raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _poll(lambda: (_describe_env(eb, env_name) or {}).get("Status"),
          lambda s: s is None or s == "Terminated",
          timeout_s=600, interval_s=2, what=f"environment {env_name} Terminated")


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Enhanced health really watches the application's own responses, both ways.

    Driving HTTP 500s degrades DescribeEnvironmentHealth with a counted 5xx total, and restoring
    200s brings it back, so the verdict is computed from the requests the application served.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    nonce = ctx.unique_name("nonce-")
    tag = [{"Key": "sim2real", "Value": "eb-health-5xx"}]

    app = ctx.unique_name("sim2real-eb-hlth-app-")
    eb.create_application(ApplicationName=app, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"sim2real-eb/{app}/v1.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce), Tagging="sim2real=eb-health-5xx")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    label = ctx.unique_name("v1-")
    eb.create_application_version(ApplicationName=app, VersionLabel=label,
                                  SourceBundle={"S3Bucket": bucket, "S3Key": key},
                                  Process=True, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application_version(
        ApplicationName=app, VersionLabel=label, DeleteSourceBundle=False))
    st = _poll(lambda: eb.describe_application_versions(
        ApplicationName=app, VersionLabels=[label])["ApplicationVersions"][0]["Status"],
        lambda s: s.upper() != "PROCESSING", timeout_s=300, interval_s=5,
        what=f"application version {label} leaving Processing")
    assert st.upper() == "PROCESSED", f"version {label!r} must process, got {st!r}"

    env = ctx.unique_name("sim2real-eb-hlth-env-")
    profile, role = _eb_iam(ctx)
    assert role, (
        "enhanced health needs the Beanstalk service role; IAM was unreachable so the "
        "enhanced-health system could not be requested and there is nothing to grade")
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
                CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
                OptionSettings=_base_options(profile, role), Tags=tag)
    ready = _poll(lambda: _describe_env(eb, env),
                  lambda e: e is not None and e.get("Status") == "Ready",
                  timeout_s=1500, interval_s=2, what=f"environment {env} reaching Ready")
    assert ready["Health"] == "Green", (
        f"the environment must settle Green before its health is driven anywhere, got "
        f"{ready['Health']!r}/{ready.get('HealthStatus')!r}")
    url = f"http://{ready['CNAME']}/"
    _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1], timeout_s=600, interval_s=2,
                what=f"{env} serving its nonce before its health is driven")

    def _health():
        return eb.describe_environment_health(EnvironmentName=env, AttributeNames=["All"])

    base = _poll(_health, lambda h: h.get("HealthStatus") == "Ok", timeout_s=600, interval_s=2,
                 what=f"DescribeEnvironmentHealth reporting Ok for the healthy {env}")
    assert base["HealthStatus"] == "Ok", (
        f"a healthy freshly deployed environment must report HealthStatus Ok, got {base!r}")

    def _drive(path, n=25):
        """n real requests, so the health agent's rolling window is fed by this check."""
        for _ in range(n):
            try:
                _http_get(ctx, url + path, timeout=8)
            except Exception:  # noqa: BLE001 — a dropped request is still traffic
                pass

    toggled = _http_get(ctx, url + "sim2real/fail-on")
    assert toggled[0] == 200, f"the toggle route must answer 200, got {toggled!r}"
    broken = _http_get(ctx, url)
    assert broken[0] == 500, (
        f"after the toggle the application must really return 500, got {broken!r} — without that "
        f"there is no 5xx traffic for the health system to see")

    def _drive_then_health():
        _drive("")
        return _health()

    sick = _poll(_drive_then_health, lambda h: h.get("HealthStatus") != "Ok", timeout_s=900,
                 interval_s=2,
                 what=f"the health system reacting to the 5xx traffic driven at {env}")
    assert sick["HealthStatus"] == "Severe", (
        f"an application returning 5xx to essentially every request must be graded Severe; real "
        f"AWS reported {sick.get('HealthStatus')!r} with causes {sick.get('Causes')!r}")
    assert sick["Color"] == "Red", (
        f"the Severe verdict must be coloured Red, got {sick.get('Color')!r} in {sick!r}")
    causes = sick.get("Causes") or []
    assert any("5xx" in c for c in causes), (
        f"the Causes must name the 5xx rate, which is what proves the health system SAW the "
        f"responses rather than inferring anything; got {causes!r}")
    codes = (sick.get("ApplicationMetrics") or {}).get("StatusCodes") or {}
    assert codes.get("Status5xx", 0) > 0, (
        f"the platform must have COUNTED the real 5xx responses; ApplicationMetrics reported "
        f"{sick.get('ApplicationMetrics')!r}")

    restored = _http_get(ctx, url + "sim2real/fail-off")
    assert restored[0] == 200, f"the restore route must answer 200, got {restored!r}"
    ok_again = _http_get(ctx, url)
    assert ok_again[1].strip() == f"sim2real-nonce={nonce}", (
        f"after the restore the application must serve its nonce again, got {ok_again!r}")

    well = _poll(_drive_then_health, lambda h: h.get("HealthStatus") == "Ok", timeout_s=900,
                 interval_s=2,
                 what=f"the health system returning {env} to Ok once the 500s stop")
    assert well["HealthStatus"] == "Ok", (
        f"the recovery half: restoring 200s must bring HealthStatus back to exactly Ok, got "
        f"{well.get('HealthStatus')!r} with causes {well.get('Causes')!r}")
    assert (well.get("ApplicationMetrics") or {}).get("StatusCodes", {}).get("Status5xx", 0) == 0, (
        f"once the 500s stop the rolling window must contain none; ApplicationMetrics reported "
        f"{well.get('ApplicationMetrics')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
