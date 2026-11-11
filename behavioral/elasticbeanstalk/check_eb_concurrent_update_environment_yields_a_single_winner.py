"""eb-concurrent-update-environment-yields-a-single-winner."""
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



CHECK = "eb-concurrent-update-environment-yields-a-single-winner"
GROUP = 'concurrency'
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
                        Tags=[{"Key": "sim2real", "Value": "eb-concurrent-update"}])
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
    # there is nothing to poll here. Correctness comes entirely from the bounded CreateEnvironment
    # retry below, which retries on exactly the propagation-refusal messages for up to 300s.
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
    """Four simultaneous UpdateEnvironment calls produce one winner, and the winner is what runs.

    The three losers get InvalidParameterValue ("... invalid state for this operation. Must be
    Ready."), and the settled value equals the winner's in the API and inside the running process.
    """
    import concurrent.futures

    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    nonce = ctx.unique_name("nonce-")
    tag = [{"Key": "sim2real", "Value": "eb-concurrent-update"}]
    ns = "aws:elasticbeanstalk:application:environment"

    app = ctx.unique_name("sim2real-eb-conc-app-")
    eb.create_application(ApplicationName=app, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"sim2real-eb/{app}/v1.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce),
                  Tagging="sim2real=eb-concurrent-update")
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

    env = ctx.unique_name("sim2real-eb-conc-env-")
    profile, role = _eb_iam(ctx)
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
                CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
                OptionSettings=_base_options(profile, role) + [
                    {"Namespace": ns, "OptionName": "SIM2REAL_WINNER", "Value": "unset"}],
                Tags=tag)
    ready = _poll(lambda: _describe_env(eb, env),
                  lambda e: e is not None and e.get("Status") == "Ready",
                  timeout_s=1500, interval_s=2, what=f"environment {env} reaching Ready")
    url = f"http://{ready['CNAME']}/"
    _http_until(ctx, url + "sim2real/env", lambda r: r[0] == 200 and "unset" in r[1], timeout_s=600,
                interval_s=2, what=f"{env} reporting the pre-contention value")

    values = [ctx.unique_name(f"w{i}-") for i in range(4)]

    def _attempt(value):
        try:
            eb.update_environment(EnvironmentName=env, OptionSettings=[
                {"Namespace": ns, "OptionName": "SIM2REAL_WINNER", "Value": value}])
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None) or {}
            code = (resp.get("Error") or {}).get("Code")
            assert code, f"a refusal carried no AWS error code: {type(exc).__name__}: {exc}"
            return ("refused", value, code)
        return ("accepted", value, None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        outcomes = list(ex.map(_attempt, values))

    accepted = [o for o in outcomes if o[0] == "accepted"]
    refused = [o for o in outcomes if o[0] == "refused"]
    assert len(accepted) == 1, (
        f"exactly ONE of four simultaneous UpdateEnvironment calls may be accepted, not "
        f"'at least one': the outcomes were {outcomes!r}")
    codes = [o[2] for o in refused]
    assert codes.count("InvalidParameterValue") == 3, (
        f"all three losers must be refused with the SAME single code; observed {codes!r}")
    winner = accepted[0][1]

    _poll(lambda: (_describe_env(eb, env) or {}).get("Status"), lambda s: s == "Ready",
          timeout_s=1500, interval_s=2,
          what=f"environment {env} settling back to Ready after the contention")

    cfg = eb.describe_configuration_settings(ApplicationName=app, EnvironmentName=env)
    hit = [o for o in cfg["ConfigurationSettings"][0]["OptionSettings"]
           if o.get("Namespace") == ns and o.get("OptionName") == "SIM2REAL_WINNER"]
    assert len(hit) == 1 and hit[0].get("Value") == winner, (
        f"the settled configuration must equal the winner's value {winner!r}; "
        f"DescribeConfigurationSettings reports {hit!r} and the losers offered "
        f"{[o[1] for o in refused]!r}")

    seen = json.loads(_http_until(ctx,
        url + "sim2real/env", lambda r: r[0] == 200 and winner in r[1], timeout_s=900,
        interval_s=2,
        what=f"the process in {env} reporting the winning value {winner!r}")[1])
    assert seen == {"SIM2REAL_WINNER": winner}, (
        f"the arbitration must reach the running process, not just the configuration store; the "
        f"application reported {seen!r} and the winner was {winner!r}")

    end = _poll(lambda: _describe_env(eb, env),
                lambda e: e is not None and e.get("Status") == "Ready"
                and e.get("Health") == "Green", timeout_s=900, interval_s=2,
                what=f"environment {env} settling Ready/Green after the contention")
    assert end["Status"] == "Ready" and end["Health"] == "Green", (
        f"contention must not strand the environment; it ended "
        f"{end['Status']!r}/{end['Health']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
