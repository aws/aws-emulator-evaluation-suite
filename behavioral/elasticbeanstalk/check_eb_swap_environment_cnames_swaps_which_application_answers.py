"""eb-swap-environment-cnames-swaps-which-application-answers."""
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



CHECK = "eb-swap-environment-cnames-swaps-which-application-answers"
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
                        Tags=[{"Key": "sim2real", "Value": "eb-swap-cnames"}])
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
    # there is nothing to poll here; the bounded CreateEnvironment retry below is what absorbs the
    # propagation delay, with a stated deadline and reason, rather than a flat sleep.
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
    """SwapEnvironmentCNAMEs really exchanges which application answers which hostname.

    The two hostnames' nonces trade places while both EndpointURLs stay put and both environments
    stay Ready/Green, which tells a CNAME swap apart from a redeploy.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    tag = [{"Key": "sim2real", "Value": "eb-swap-cnames"}]
    na = ctx.unique_name("nonceA-")
    nb = ctx.unique_name("nonceB-")

    app = ctx.unique_name("sim2real-eb-swap-app-")
    eb.create_application(ApplicationName=app, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    bucket = eb.create_storage_location()["S3Bucket"]
    stack = _solution_stack(eb)
    profile, role = _eb_iam(ctx)

    def _version(nonce, side):
        key = f"sim2real-eb/{app}/{side}.zip"
        s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce),
                      Tagging="sim2real=eb-swap-cnames")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
        label = ctx.unique_name(f"v-{side}-")
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
        return label

    label_a, label_b = _version(na, "a"), _version(nb, "b")
    env_a = ctx.unique_name("sim2real-eb-swap-a-")
    env_b = ctx.unique_name("sim2real-eb-swap-b-")
    # Both created before either is polled, so the two provisioning waits overlap.
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env_a, VersionLabel=label_a,
                CNAMEPrefix=env_a, SolutionStackName=stack,
                OptionSettings=_base_options(profile, role), Tags=tag)
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env_b, VersionLabel=label_b,
                CNAMEPrefix=env_b, SolutionStackName=stack,
                OptionSettings=_base_options(profile, role), Tags=tag)
    ready_a = _poll(lambda: _describe_env(eb, env_a),
                    lambda e: e is not None and e.get("Status") == "Ready",
                    timeout_s=1800, interval_s=2, what=f"environment {env_a} reaching Ready")
    ready_b = _poll(lambda: _describe_env(eb, env_b),
                    lambda e: e is not None and e.get("Status") == "Ready",
                    timeout_s=1800, interval_s=2, what=f"environment {env_b} reaching Ready")

    cname_a, cname_b = ready_a["CNAME"], ready_b["CNAME"]
    ep_a, ep_b = ready_a["EndpointURL"], ready_b["EndpointURL"]
    assert cname_a != cname_b, f"two environments must hold distinct CNAMEs, got {cname_a!r}"
    url_a, url_b = f"http://{cname_a}/", f"http://{cname_b}/"

    got_a = _http_until(ctx, url_a, lambda r: r[0] == 200 and na in r[1], timeout_s=600,
                        interval_s=2, what=f"{env_a} serving nonce-A over {cname_a}")
    got_b = _http_until(ctx, url_b, lambda r: r[0] == 200 and nb in r[1], timeout_s=600,
                        interval_s=2, what=f"{env_b} serving nonce-B over {cname_b}")
    assert got_a[1].strip() == f"sim2real-nonce={na}", (
        f"the baseline that makes the swap meaningful: {cname_a!r} must serve nonce-A, got "
        f"{got_a!r}")
    assert got_b[1].strip() == f"sim2real-nonce={nb}", (
        f"the baseline that makes the swap meaningful: {cname_b!r} must serve nonce-B, got "
        f"{got_b!r}")

    eb.swap_environment_cnames(SourceEnvironmentName=env_a, DestinationEnvironmentName=env_b)
    observed = []

    def _both():
        a, b = _describe_env(eb, env_a) or {}, _describe_env(eb, env_b) or {}
        observed.append({"a": (a.get("Status"), a.get("Health"), a.get("EndpointURL")),
                         "b": (b.get("Status"), b.get("Health"), b.get("EndpointURL"))})
        return a.get("CNAME"), b.get("CNAME")

    swapped = _poll(_both, lambda p: p == (cname_b, cname_a), timeout_s=600, interval_s=2,
                    what=f"DescribeEnvironments reporting the CNAMEs exchanged "
                         f"({cname_a!r} <-> {cname_b!r})")
    assert swapped == (cname_b, cname_a), (
        f"the CNAMEs must be exactly exchanged; before ({cname_a!r}, {cname_b!r}), after "
        f"{swapped!r}")

    # BOTH environments pass through
    # Status 'Updating' during a SwapEnvironmentCNAMEs, so "Status never left Ready" is not the
    # invariant. What must hold — and what "the swap did not restart the applications" actually
    # means — is that HEALTH never left Green and neither instance was replaced, i.e. the
    # EndpointURL never moved. Both are asserted over every observation, and neither environment
    # may be seen tearing down or relaunching.
    off_green = [o for o in observed if o["a"][1] != "Green" or o["b"][1] != "Green"]
    assert not off_green, (
        f"a CNAME swap must not disturb either application's health: observed non-Green states "
        f"during the swap: {off_green!r}")
    moved = [o for o in observed if o["a"][2] != ep_a or o["b"][2] != ep_b]
    assert not moved, (
        f"a CNAME swap must not replace either instance: the EndpointURLs were {ep_a!r}/{ep_b!r} "
        f"and these observations disagree: {moved!r}")
    restarted = [o for o in observed
                 if o["a"][0] not in ("Ready", "Updating")
                 or o["b"][0] not in ("Ready", "Updating")]
    assert not restarted, (
        f"a CNAME swap must not relaunch or tear down either environment; observed: "
        f"{restarted!r}")

    # DNS propagation after a swap is not instant and not bounded by AWS, so retry generously —
    # and fail, never skip, if the hostnames never trade places.
    after_a = _http_until(ctx, url_a, lambda r: r[0] == 200 and nb in r[1], timeout_s=900,
                          interval_s=2,
                          what=f"{cname_a!r} serving nonce-B {nb!r} after the swap")
    after_b = _http_until(ctx, url_b, lambda r: r[0] == 200 and na in r[1], timeout_s=900,
                          interval_s=2,
                          what=f"{cname_b!r} serving nonce-A {na!r} after the swap")
    assert after_a[1].strip() == f"sim2real-nonce={nb}", (
        f"after the swap {cname_a!r} must serve nonce-B; got {after_a!r}")
    assert after_b[1].strip() == f"sim2real-nonce={na}", (
        f"after the swap {cname_b!r} must serve nonce-A; got {after_b!r}")

    # The instance/load-balancer endpoints do NOT swap: each still reaches its own application.
    # That is what proves the exchange happened at the CNAME layer rather than by redeploying.
    ep_got_a = _http_until(ctx, f"http://{ep_a}/", lambda r: r[0] == 200, timeout_s=300,
                           interval_s=2, what=f"the unswapped EndpointURL {ep_a!r} answering")
    ep_got_b = _http_until(ctx, f"http://{ep_b}/", lambda r: r[0] == 200, timeout_s=300,
                           interval_s=2, what=f"the unswapped EndpointURL {ep_b!r} answering")
    assert ep_got_a[1].strip() == f"sim2real-nonce={na}", (
        f"{env_a}'s own endpoint must still reach {env_a}'s application (nonce-A); got "
        f"{ep_got_a!r}")
    assert ep_got_b[1].strip() == f"sim2real-nonce={nb}", (
        f"{env_b}'s own endpoint must still reach {env_b}'s application (nonce-B); got "
        f"{ep_got_b!r}")

    end_a, end_b = _describe_env(eb, env_a), _describe_env(eb, env_b)
    assert end_a["Health"] == "Green" and end_b["Health"] == "Green", (
        f"both environments must still be Green after the swap; got {end_a['Health']!r} and "
        f"{end_b['Health']!r}")
    assert end_a["EndpointURL"] == ep_a and end_b["EndpointURL"] == ep_b, (
        f"the EndpointURLs must not move; {ep_a!r}/{ep_b!r} became "
        f"{end_a['EndpointURL']!r}/{end_b['EndpointURL']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
