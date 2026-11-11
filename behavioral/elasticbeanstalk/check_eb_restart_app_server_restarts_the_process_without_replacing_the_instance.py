"""eb-restart-app-server-restarts-the-process-without-replacing-the-instance."""
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


CHECK = "eb-restart-app-server-restarts-the-process-without-replacing-the-instance"
GROUP = "environment-data-plane"
SERVICES = ["elasticbeanstalk"]

#: Lets a Ready environment with nothing listening on the CNAME fail as a missing data plane.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals that mean "the IAM principal this check just created is not visible
#: to Elastic Beanstalk yet". Retried, bounded, in `_create_env`; anything else re-raises.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: The deployed application: stdlib only, so every HTTP assertion is over a nonce the check minted.
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, pred, *, timeout_s: float, interval_s: float, what: str, ctx=None):
    """Poll ``probe()`` until ``pred`` holds; raise AssertionError quoting the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
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
    """(status, body) where a transport failure becomes the status ``"<no-response>"``.

    Used where unreachability is the measurement rather than an error.
    """
    try:
        return _http_get(ctx, url, timeout=timeout)
    except (OSError, http.client.HTTPException) as exc:
        # Narrow on purpose: a refused connection, a reset and a truncated status line are the
        # measurement; anything else propagates.
        return "<no-response>", f"{type(exc).__name__}: {exc}"


def _http_until(ctx, url: str, pred, *, timeout_s: float, interval_s: float = 2.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds.

    A connection failure after the budget fails: a Ready environment nobody can reach is a defect.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = _http_probe(ctx, url, timeout=min(20.0, max(1.0, deadline - time.monotonic())))
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what} at {url!r}: the run budget ended first; not graded")
            raise AssertionError(
                f"{DATAPLANE_MARKER}: {what} — nothing satisfying the condition came back from "
                f"{url!r} within {timeout_s}s; last outcome {last!r}. A provisioned-but-"
                f"unconnectable environment is a failure, not an environment limitation.")
        time.sleep(interval_s)


def _solution_stack(eb) -> str:
    """A current AL2023 Python solution stack, resolved from the service, never hardcoded.

    Python: its streamed log set is documented and the bundle is stdlib-only.
    """
    stacks = eb.list_available_solution_stacks().get("SolutionStacks") or []
    py = [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
    assert py, (
        f"this check needs an Amazon Linux 2023 Python solution stack; "
        f"ListAvailableSolutionStacks offered none, returning {stacks[:12]!r}")
    return py[0]


def _eb_iam(ctx, marker: str, extra_instance_policies=()):
    """The instance profile + service role an environment needs, with LIFO teardown.

    Raises if IAM is unreachable rather than launching without an instance profile.
    """
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
    """The minimum option set for an environment; `t3.micro` is a deliberate literal."""
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

    IAM exposes no signal that a new principal is usable by another service, so a bounded retry
    that re-raises the refusal at its deadline replaces a sleep.
    """
    env_name = kwargs["EnvironmentName"]
    create_deadline_s = _budget_s(ctx, 300.0)
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
                if code in _IAM_PROPAGATION_CODES and role_ish and _budget_spent(ctx):
                    raise TimeoutError(f"CreateEnvironment {env_name} waiting for its IAM roles "
                                       f"to propagate: the run budget ended first; not "
                                       f"graded") from exc
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _terminate(eb, env_name))
    return resp


def _terminate(eb, env_name):
    """Terminate and poll to Terminated. Registered via ctx.on_cleanup, so it runs LIFO.

    Routinely takes 180-420s; cutting it off leaks a live EC2 instance and Auto Scaling group.
    """
    terminate_deadline_s = 900.0
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the wanted state; anything else re-raises.
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
    # Case-folded: real AWS answers "PROCESSING"/"PROCESSED" while the Smithy model declares
    # Processing/Processed.
    process_deadline_s = _budget_s(ctx, 300.0)
    status = _poll(
        lambda: eb.describe_application_versions(
            ApplicationName=app, VersionLabels=[label])["ApplicationVersions"][0]["Status"],
        lambda s: s.upper() != "PROCESSING",
        timeout_s=process_deadline_s, interval_s=1,
        what=f"application version {label} leaving Processing", ctx=ctx)
    assert status.upper() == "PROCESSED", (
        f"version {label!r} must process cleanly before it can be deployed; "
        f"DescribeApplicationVersions reports Status={status!r}")
    return label, bucket, key


def _ready(eb, env_name, what_suffix="", timeout_s=1500.0, ctx=None):
    """Wait for the environment to settle Ready; the poll never ends on Terminated/Terminating."""
    env = _poll(lambda: _describe_env(eb, env_name),
                lambda e: e is not None and e.get("Status") == "Ready",
                timeout_s=timeout_s, interval_s=2,
                what=f"environment {env_name} reaching Ready{what_suffix}", ctx=ctx)
    assert env["Status"] == "Ready", (
        f"settled Status must be exactly Ready, got {env['Status']!r}")
    return env


def _new_application(ctx, eb, prefix, marker):
    """Create the application, registering its delete first so LIFO teardown runs it after every
    environment terminate; the other order races a still-terminating environment and leaks it."""
    app = ctx.unique_name(prefix)
    eb.create_application(ApplicationName=app, Tags=[{"Key": "sim2real", "Value": marker}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    return app


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """RestartAppServer restarts the application process (new boot id, reset in-memory counter,
    lower uptime) while the instance-id set, Ready status and CNAME stay unchanged, unlike
    RebuildEnvironment, which replaces the instances.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_RestartAppServer.html
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    marker = "eb-restart-app-server"
    nonce = ctx.unique_name("nonce-")

    app = _new_application(ctx, eb, "sim2real-eb-rst-app-", marker)
    label, _bucket, _key = _publish_version(ctx, eb, s3, app, marker, nonce)

    env = ctx.unique_name("sim2real-eb-rst-env-")
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
    ready = _ready(eb, env, timeout_s=_budget_s(ctx, 1500.0), ctx=ctx)
    url = f"http://{ready['CNAME']}/"
    boot_url = f"{url}sim2real/boot"

    def _boot():
        r = _http_until(ctx, boot_url, lambda x: x[0] == 200, timeout_s=_budget_s(ctx, 600.0),
                        interval_s=1,
                        what=f"{env} reporting its process boot identity")
        return json.loads(r[1])

    # Three strictly increasing reads make the post-restart `hits == 1` meaningful.
    first = _boot()
    assert first["nonce"] == nonce, (
        f"the running process must be the bundle this check uploaded; /sim2real/boot reported "
        f"nonce {first['nonce']!r}, expected {nonce!r}")
    counts = [first["hits"]]
    for _ in range(2):
        counts.append(_boot()["hits"])
    assert counts == sorted(counts) and len(set(counts)) == 3, (
        f"the in-memory request counter must strictly increase across three reads, otherwise its "
        f"reset below proves nothing; the process reported {counts!r}")
    boot_before = first["boot"]

    resources_before = eb.describe_environment_resources(
        EnvironmentName=env)["EnvironmentResources"]
    instances_before = {i["Id"] for i in resources_before["Instances"]}
    assert instances_before, (
        f"DescribeEnvironmentResources must report at least one instance for a Ready environment "
        f"that is serving HTTP; it reported {resources_before!r}")

    # The documented response is empty, so it is never the verdict.
    eb.restart_app_server(EnvironmentName=env)

    after = _poll(_boot, lambda d: d["boot"] != boot_before, timeout_s=_budget_s(ctx, 300.0),
                  interval_s=1,
                  what=(f"the application process on {env} reporting a boot identity different "
                        f"from the pre-restart {boot_before!r}"), ctx=ctx)
    assert after["boot"] != boot_before, (
        f"RestartAppServer must restart the application process, so its boot identity must "
        f"change; it stayed {boot_before!r}")
    assert after["hits"] == 1, (
        f"the restarted process must have lost the in-memory state of the old one: the first "
        f"request after the restart is request 1, but the process reported hits={after['hits']!r} "
        f"(pre-restart reads were {counts!r})")
    assert after["nonce"] == nonce, (
        f"the restart must not change which bundle is running; the process reported nonce "
        f"{after['nonce']!r}, expected {nonce!r}")
    assert after["uptime_s"] < first["uptime_s"], (
        f"the restarted process must be YOUNGER than the one it replaced; it reported uptime "
        f"{after['uptime_s']!r}s against the pre-restart {first['uptime_s']!r}s")

    # The same instances: the contrast with RebuildEnvironment, which replaces them.
    resources_after = eb.describe_environment_resources(
        EnvironmentName=env)["EnvironmentResources"]
    instances_after = {i["Id"] for i in resources_after["Instances"]}
    assert instances_after == instances_before, (
        f"RestartAppServer restarts the application container server; it must NOT replace the "
        f"instance. DescribeEnvironmentResources reported {instances_before!r} before and "
        f"{instances_after!r} after — a disjoint set would mean this was implemented as a rebuild")

    # The environment may report Updating for a moment after the process restarts.
    settled = _poll(lambda: _describe_env(eb, env),
                    lambda e: e is not None and e.get("Status") == "Ready",
                    timeout_s=_budget_s(ctx, 300.0), interval_s=1,
                    what=f"environment {env} being Ready after an application-server restart",
                    ctx=ctx)
    assert settled is not None and settled["Status"] == "Ready", (
        f"the environment must be Ready after an application-server restart, got "
        f"{settled!r}")
    assert settled["CNAME"] == ready["CNAME"], (
        f"a restart must not move the CNAME; it was {ready['CNAME']!r} and is now "
        f"{settled['CNAME']!r}")

    # The restarted process serves the plain "/" route again.
    served = _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1],
                         timeout_s=_budget_s(ctx, 300.0), interval_s=1,
                         what=f"{env} serving its own content again after the restart")
    assert served[1].strip() == f"sim2real-nonce={nonce}", (
        f"after the restart the CNAME must serve exactly what server.py writes, got "
        f"{served[1]!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
