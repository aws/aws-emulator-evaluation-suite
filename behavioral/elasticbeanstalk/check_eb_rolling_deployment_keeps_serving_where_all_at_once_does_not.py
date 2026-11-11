"""eb-rolling-deployment-keeps-serving-where-all-at-once-does-not."""
from __future__ import annotations

import threading
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


CHECK = "eb-rolling-deployment-keeps-serving-where-all-at-once-does-not"
GROUP = "environment-data-plane"
SERVICES = ["elasticbeanstalk"]

#: Carried in the failure detail when an environment reports Ready while nothing listens on the
#: CNAME, so the miss is graded as a data-plane FAIL rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals that mean "the IAM principal this check just created is not visible
#: to Elastic Beanstalk yet". Retried, bounded, in `_create_env`; anything else re-raises.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: The deployed application. stdlib only, so the bundle needs no dependency install and every HTTP
#: assertion is an identity law over a nonce the check minted.
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
    ``extra`` adds arbitrary members (a `.ebextensions/*.config`, a static asset)."""
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
    """(status, body) where a transport failure becomes the status ``"<no-response>"``, so an
    unreachable CNAME during a deployment is recorded as a data point."""
    try:
        return _http_get(ctx, url, timeout=timeout)
    except (OSError, http.client.HTTPException) as exc:
        # Narrow on purpose: a refused connection, a reset and a truncated status line are the
        # measurement. Anything else (a bug in this check) still propagates.
        return "<no-response>", f"{type(exc).__name__}: {exc}"


def _http_until(ctx, url: str, pred, *, timeout_s: float, interval_s: float = 2.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds. A connection failure after the
    budget is a FAILURE, never a skip."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = _http_probe(ctx, url, timeout=min(20.0, max(2.0, timeout_s)))
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
    """A current AL2023 Python solution stack, resolved from the service, never hardcoded."""
    stacks = eb.list_available_solution_stacks().get("SolutionStacks") or []
    py = [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
    assert py, (
        f"this check needs an Amazon Linux 2023 Python solution stack; "
        f"ListAvailableSolutionStacks offered none, returning {stacks[:12]!r}")
    return py[0]


def _eb_iam(ctx, marker: str, extra_instance_policies=()):
    """The instance profile + service role an environment needs, with LIFO teardown. Raises if
    IAM is unreachable: an environment without an instance profile is a different subject."""
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
    """The minimum option set for a gradeable environment. `t3.micro` is the subject of the
    request, not an account-varying quota."""
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
    IAM exposes no condition reporting that a principal is usable by another service."""
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
    """Terminate and poll to Terminated (routinely 180-420s). Registered via ctx.on_cleanup, so it
    runs LIFO."""
    terminate_deadline_s = 900.0
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the state this function wants. Any other
        # code re-raises rather than being swallowed.
        if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue", "ResourceNotFoundException"):
            raise
    _poll(lambda: (_describe_env(eb, env_name) or {}).get("Status"),
          lambda s: s is None or s == "Terminated",
          timeout_s=terminate_deadline_s, interval_s=3,
          what=f"environment {env_name} reaching Terminated")


def _publish_version(ctx, eb, s3, app, marker, nonce, extra=None, label_prefix="v-"):
    """Upload a source bundle and create a PROCESSED application version from it.
    Returns (version_label, bucket, key). The Processed wait is bounded and raises."""
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
    # Compared case-folded on purpose: real AWS answers "PROCESSING"/"PROCESSED" while the Smithy
    # model declares Processing/Processed.
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


def _ready(ctx, eb, env_name, what_suffix=""):
    """Wait for the environment to settle Ready. The terminal set excludes every failure value, so
    a poll cannot terminate on `Terminated` or `Terminating`."""
    ready_deadline_s = _budget_s(ctx, 1500.0)
    env = _poll(lambda: _describe_env(eb, env_name),
                lambda e: e is not None and e.get("Status") == "Ready",
                timeout_s=ready_deadline_s, interval_s=2,
                what=f"environment {env_name} reaching Ready{what_suffix}", ctx=ctx)
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """During a Rolling deployment (BatchSize=1, 2 instances) the same CNAME serves BOTH the old and
    the new nonce, a mixed-version window an atomic swap cannot produce; neither Rolling nor
    AllAtOnce may cause more than an incidental blip of non-200 samples.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.rolling-version-deploy.html
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    marker = "eb-deploy-policy"
    cmd_ns = "aws:elasticbeanstalk:command"
    asg_ns = "aws:autoscaling:asg"
    n1 = ctx.unique_name("v1-nonce-")
    n2 = ctx.unique_name("v2-nonce-")
    n3 = ctx.unique_name("v3-nonce-")

    app = _new_application(ctx, eb, "sim2real-eb-pol-app-", marker)
    l1, _b1, _k1 = _publish_version(ctx, eb, s3, app, marker, n1, label_prefix="v1-")
    l2, _b2, _k2 = _publish_version(ctx, eb, s3, app, marker, n2, label_prefix="v2-")
    l3, _b3, _k3 = _publish_version(ctx, eb, s3, app, marker, n3, label_prefix="v3-")

    env = ctx.unique_name("sim2real-eb-pol-env-")
    profile, role = _eb_iam(ctx, marker)
    _create_env(
        ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=l1,
        CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
        OptionSettings=_base_options(profile, role, single_instance=False) + [
            # Two instances, fixed, so a batch of 1 leaves exactly one serving. MinSize/MaxSize are
            # the SUBJECT of the request, not an account quota.
            {"Namespace": asg_ns, "OptionName": "MinSize", "Value": "2"},
            {"Namespace": asg_ns, "OptionName": "MaxSize", "Value": "2"},
        ],
        Tags=[{"Key": "sim2real", "Value": marker}])
    ready = _ready(ctx, eb, env, " as a load-balanced 2-instance environment")
    url = f"http://{ready['CNAME']}/"
    _http_until(ctx, url, lambda r: r[0] == 200 and n1 in r[1], timeout_s=900.0, interval_s=2,
                what=f"the load-balanced {env} serving v1's nonce {n1!r} before any deployment")

    instances = {
        i["Id"] for i in
        eb.describe_environment_resources(EnvironmentName=env)["EnvironmentResources"]["Instances"]
    }
    assert len(instances) == 2, (
        f"a Rolling batch of 1 only means something with more than one instance: this environment "
        f"must be running exactly the 2 instances requested, but "
        f"DescribeEnvironmentResources reported {instances!r}")

    def _set_policy(options):
        """Configuration-only update: no version change, so nothing is deployed by it."""
        resp = eb.update_environment(EnvironmentName=env, OptionSettings=options)
        assert resp["Status"] == "Updating", (
            f"setting the deployment policy must move the environment to Updating, got "
            f"{resp['Status']!r}")
        _poll(lambda: (_describe_env(eb, env) or {}).get("Status"), lambda s: s == "Ready",
              timeout_s=_budget_s(ctx, 900.0), interval_s=2,
              what=f"environment {env} settling Ready after {options!r}", ctx=ctx)

    def _deploy_and_sample(version_label, expect_nonce, policy_name):
        """Deploy *version_label* and sample the CNAME every 100ms until the deploy settles.

        Returns ``(samples, elapsed_s)``. 100ms because a deploy can settle within a few seconds,
        and a simultaneous restart can fall inside one gap between probes."""
        samples: list[tuple[object, str]] = []
        stop = threading.Event()
        sampler_deadline_s = _budget_s(ctx, 900.0)

        def _sample():
            end = time.monotonic() + sampler_deadline_s
            while not stop.is_set() and time.monotonic() < end:
                samples.append(_http_probe(ctx, url, timeout=5.0))
                stop.wait(0.1)

        thread = threading.Thread(target=_sample, daemon=True)
        thread.start()
        deploy_start = time.monotonic()
        try:
            resp = eb.update_environment(EnvironmentName=env, VersionLabel=version_label)
            assert resp["Status"] == "Updating", (
                f"deploying {version_label!r} under {policy_name} must move the environment to "
                f"Updating, got {resp['Status']!r}")
            _poll(lambda: (_describe_env(eb, env) or {}).get("Status"), lambda s: s == "Ready",
                  timeout_s=_budget_s(ctx, 900.0), interval_s=2,
                  what=f"environment {env} settling Ready after the {policy_name} deployment",
                  ctx=ctx)
        finally:
            elapsed_s = time.monotonic() - deploy_start
            stop.set()
            thread.join(timeout=_budget_s(ctx, 30.0))
        if thread.is_alive() and _budget_spent(ctx):
            raise TimeoutError("the sampler thread stopping: the run budget ended first; not graded")
        assert not thread.is_alive(), "the sampler thread did not stop; its samples are unusable"

        # The instrument's own positive control: a deployment that produced almost no samples was
        # not observed, and any verdict over those samples would be meaningless.
        assert len(samples) >= 20, (
            f"the {policy_name} deployment must have been sampled enough times to say anything "
            f"about availability; only {len(samples)} samples were taken")
        served = _http_until(ctx,
            url, lambda r: r[0] == 200 and expect_nonce in r[1], timeout_s=600.0, interval_s=2,
            what=f"{env} serving {version_label!r}'s nonce {expect_nonce!r} after the deployment")
        assert served[1].strip() == f"sim2real-nonce={expect_nonce}", (
            f"the {policy_name} deployment must really have changed what is served; the CNAME "
            f"returned {served[1]!r}, expected the nonce of {version_label!r}")
        return samples, elapsed_s

    def _unavailable(samples):
        return [s for s in samples if s[0] != 200]

    # --- Leg 1: Rolling, batch of 1 out of 2. ---
    _set_policy([
        {"Namespace": cmd_ns, "OptionName": "DeploymentPolicy", "Value": "Rolling"},
        {"Namespace": cmd_ns, "OptionName": "BatchSizeType", "Value": "Fixed"},
        {"Namespace": cmd_ns, "OptionName": "BatchSize", "Value": "1"},
    ])
    rolling, rolling_elapsed_s = _deploy_and_sample(l2, n2, "Rolling(Fixed,1)")
    rolling_down = _unavailable(rolling)
    rolling_bodies = {s[1].strip() for s in rolling if s[0] == 200}

    # --- Leg 2: AllAtOnce, same environment, same instances, same bundle size. ---
    _set_policy([{"Namespace": cmd_ns, "OptionName": "DeploymentPolicy", "Value": "AllAtOnce"}])
    all_at_once, all_at_once_elapsed_s = _deploy_and_sample(l3, n3, "AllAtOnce")
    aao_down = _unavailable(all_at_once)

    # --- The mixed-version window: only a real batched rollout can produce it.
    old_body = f"sim2real-nonce={n1}"
    new_body = f"sim2real-nonce={n2}"
    assert old_body in rolling_bodies and new_body in rolling_bodies, (
        f"a Rolling deployment leaves some instances on the old version while completed batches "
        f"serve the new one, so the same hostname must return BOTH within the window. Over "
        f"{len(rolling)} samples the CNAME returned the distinct bodies {sorted(rolling_bodies)!r}"
        f"; expected both {old_body!r} and {new_body!r}")

    # --- Bounded-availability sanity check, NOT the discriminator: a 2-instance environment behind
    # --- an ALB does not reliably lose both targets at once, and an ALB deregistration delay can
    # --- cause a single-sample blip. This catches a target that goes dark for a real stretch.
    for policy_name, down, total in (
            ("Rolling", rolling_down, rolling), ("AllAtOnce", aao_down, all_at_once)):
        cap = max(3, round(len(total) * 0.01))
        assert len(down) <= cap, (
            f"{policy_name} must keep serving throughout, with at most an incidental blip — not a "
            f"real outage: {len(down)} of {len(total)} samples were not 200 (cap {cap}), first "
            f"few {down[:3]!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
