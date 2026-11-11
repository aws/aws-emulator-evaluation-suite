"""eb-retrieved-environment-info-carries-the-applications-own-log-line."""
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


CHECK = "eb-retrieved-environment-info-carries-the-applications-own-log-line"
GROUP = "environment-data-plane"
SERVICES = ["elasticbeanstalk"]

#: Failure prefix for an environment reported Ready while nothing answers on its CNAME.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals that mean "the IAM principal this check just created is not visible
#: to Elastic Beanstalk yet". Retried, bounded, in `_create_env`; anything else re-raises.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: A stdlib-only app serving a check-minted nonce, so every HTTP assertion is an identity law.
#: /sim2real/log writes "SIM2REAL-LOG-LINE <NONCE>" to the process stdout and echoes it.
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
    """A source bundle serving ``nonce``: a Procfile web command plus the stdlib server above."""
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
        # Narrow on purpose: a refused connection, a reset and a truncated status line are the
        # measurement. Anything else (a bug in this check) still propagates.
        return "<no-response>", f"{type(exc).__name__}: {exc}"


def _http_until(ctx, url: str, pred, *, timeout_s: float, interval_s: float = 10.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds; unreachable after budget fails."""
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

    On this platform the app's stdout is written to /var/log/web.stdout.log.
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
    """The minimum option set for a gradeable environment."""
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

    IAM has no signal that a new principal is usable by another service, so a retry replaces a sleep.
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
    """Terminate and poll to Terminated; this teardown routinely runs 180-420s."""
    terminate_deadline_s = 900.0
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone is the wanted state.
        if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue", "ResourceNotFoundException"):
            raise
    _poll(lambda: (_describe_env(eb, env_name) or {}).get("Status"),
          lambda s: s is None or s == "Terminated",
          timeout_s=terminate_deadline_s, interval_s=15,
          what=f"environment {env_name} reaching Terminated")


def _publish_version(ctx, eb, s3, app, marker, nonce, extra=None, label_prefix="v-"):
    """Upload a source bundle and create a PROCESSED application version from it.

    Returns (version_label, bucket, key).
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
    # Case-folded: real AWS answers "PROCESSING"/"PROCESSED" while the model declares Processing.
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
    """Wait for the environment to settle exactly Ready; a failure status never ends the poll."""
    ready_deadline_s = 1500.0
    env = _poll(lambda: _describe_env(eb, env_name),
                lambda e: e is not None and e.get("Status") == "Ready",
                timeout_s=ready_deadline_s, interval_s=20,
                what=f"environment {env_name} reaching Ready{what_suffix}")
    assert env["Status"] == "Ready", (
        f"settled Status must be exactly Ready, got {env['Status']!r}")
    return env


def _new_application(ctx, eb, prefix, marker):
    """Create the application, registering its delete FIRST so that under LIFO teardown it runs
    LAST — after every environment terminate registered later. Registering it the other way round
    races the still-terminating environment and the environment leaks."""
    app = ctx.unique_name(prefix)
    eb.create_application(ApplicationName=app, Tags=[{"Key": "sim2real", "Value": marker}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    return app


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """RetrieveEnvironmentInfo's tail URL serves real log bytes holding a line the app printed.

    An unrequested bundle must be empty and the tail must name the environment's real instances.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    marker = "eb-env-info-bytes"
    nonce = ctx.unique_name("nonce-")

    app = _new_application(ctx, eb, "sim2real-eb-info-app-", marker)
    label, _bucket, _key = _publish_version(ctx, eb, s3, app, marker, nonce)

    env = ctx.unique_name("sim2real-eb-info-env-")
    profile, role = _eb_iam(ctx, marker)
    _create_env(
        ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
        CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
        OptionSettings=[
            *_base_options(profile, role),
            {"Namespace": "aws:ec2:vpc", "OptionName": "VPCId", "Value": ctx.network().vpc_id},
            {"Namespace": "aws:ec2:vpc", "OptionName": "Subnets",
             "Value": ctx.network().subnet_ids[0]},
            {"Namespace": "aws:ec2:vpc", "OptionName": "AssociatePublicIpAddress",
             "Value": "true"},
        ],
        Tags=[{"Key": "sim2real", "Value": marker}])
    ready = _ready(eb, env)
    url = f"http://{ready['CNAME']}/"
    _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1], timeout_s=600.0, interval_s=10,
                what=f"{env} serving its own nonce before any log line is written")

    # Exact equality to empty: an InfoType never requested must return nothing.
    unrequested = eb.retrieve_environment_info(
        EnvironmentName=env, InfoType="bundle").get("EnvironmentInfo", [])
    assert unrequested == [], (
        f"RetrieveEnvironmentInfo must return nothing for an InfoType this check never requested; "
        f"without that, a populated 'tail' below could just be a backend that answers every info "
        f"request. InfoType='bundle' returned {unrequested!r}")

    # Mint the log line inside the running process.
    expected_line = f"SIM2REAL-LOG-LINE {nonce}"
    logged = _http_get(ctx, f"{url}sim2real/log")
    assert logged[0] == 200 and logged[1].strip() == expected_line, (
        f"the application must confirm it wrote the log line to its own stdout; the route "
        f"returned {logged!r}, expected 200 and {expected_line!r}")

    resources = eb.describe_environment_resources(EnvironmentName=env)["EnvironmentResources"]
    real_instances = {i["Id"] for i in resources["Instances"]}
    assert real_instances, (
        f"DescribeEnvironmentResources must report the instances of an environment that is serving "
        f"HTTP; it reported {resources!r}")

    # Request the tail, fetch its URL, and demand the bytes.
    eb.request_environment_info(EnvironmentName=env, InfoType="tail")
    infos = _poll(
        lambda: eb.retrieve_environment_info(
            EnvironmentName=env, InfoType="tail").get("EnvironmentInfo") or [],
        lambda lst: bool(lst),
        timeout_s=600.0, interval_s=15,
        what=f"RetrieveEnvironmentInfo returning a tail entry for {env}")

    reported_instances = {i.get("Ec2InstanceId") for i in infos}
    assert reported_instances == real_instances, (
        f"the tail must be attributed to the environment's REAL instances: "
        f"RetrieveEnvironmentInfo reported {reported_instances!r} and "
        f"DescribeEnvironmentResources reported {real_instances!r}")

    fetched = []
    for info in infos:
        message = info.get("Message") or ""
        assert not (p := ctx.published_url_mismatch(message)), p
        status, body = _http_get(ctx, message, timeout=60.0)
        assert status == 200, (
            f"{DATAPLANE_MARKER}: the URL Elastic Beanstalk published for the tail of {env} must "
            f"actually serve the log bytes; fetching it returned status {status!r} with body "
            f"{body[:200]!r}")
        fetched.append(body)

    # The fetched bytes must contain the line the running application printed.
    joined = "\n".join(fetched)
    assert expected_line in joined, (
        f"the retrieved tail must contain the line the application printed to stdout. Expected "
        f"{expected_line!r} somewhere in {len(joined)} fetched bytes; the tail ended with "
        f"{joined[-300:]!r}")
    assert "/var/log/" in joined, (
        f"the retrieved tail must be the real multi-file tail, which names the on-instance paths "
        f"it concatenates; no '/var/log/' section header appeared in {len(joined)} bytes, ending "
        f"{joined[-300:]!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
