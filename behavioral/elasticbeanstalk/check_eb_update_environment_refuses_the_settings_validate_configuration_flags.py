"""eb-update-environment-refuses-the-settings-validate-configuration-flags."""
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



CHECK = "eb-update-environment-refuses-the-settings-validate-configuration-flags"
GROUP = 'errors'
SERVICES = ['elasticbeanstalk']

#: Prefixes the failure raised when a Ready environment serves nothing on its CNAME.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The application the check deploys: stdlib only, so the bundle needs no dependency install and
#: serves a nonce this check minted.
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
    """Poll a real HTTP GET until ``pred((status, body))`` holds; a Ready but unreachable
    environment fails."""
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
    """Create the instance profile and service role an environment needs; returns both names."""
    iam = ctx.client("iam")

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": "eb-bad-option"}])
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
    # IAM propagation lag is absorbed by the bounded CreateEnvironment retry in _create_env.
    return profile, svc_role


def _create_public_vpc(ctx):
    """Create a VPC with one public subnet, so the launch never depends on a default VPC.

    Its cleanup is registered before the environment's, so it runs after it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eb-vpc-")
    tags = [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tags}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.42.0.0/24", AvailabilityZone=sorted(z["ZoneName"] for z in zones)[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": tags}]
    )["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
    return vpc_id, subnet_id


def _vpc_options(vpc_id, subnet_id):
    return [
        {"Namespace": "aws:ec2:vpc", "OptionName": "VPCId", "Value": vpc_id},
        {"Namespace": "aws:ec2:vpc", "OptionName": "Subnets", "Value": subnet_id},
        {"Namespace": "aws:ec2:vpc", "OptionName": "AssociatePublicIpAddress", "Value": "true"},
    ]


def _delete_vpc(ec2, vpc_id, timeout_s=240.0, interval_s=2.0):
    """Tear the VPC down, retrying while the environment's network interfaces drain."""
    from botocore.exceptions import ClientError

    flt = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            for sn in ec2.describe_subnets(Filters=flt)["Subnets"]:
                ec2.delete_subnet(SubnetId=sn["SubnetId"])
            for rt in ec2.describe_route_tables(Filters=flt)["RouteTables"]:
                if not any(a.get("Main") for a in rt.get("Associations", [])):
                    ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
            igws = ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )["InternetGateways"]
            for igw in igws:
                ec2.detach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
                ec2.delete_internet_gateway(InternetGatewayId=igw["InternetGatewayId"])
            for sg in ec2.describe_security_groups(Filters=flt)["SecurityGroups"]:
                if sg["GroupName"] != "default":
                    ec2.delete_security_group(GroupId=sg["GroupId"])
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _base_options(profile, service_role, network):
    """The minimum option set for a single-instance environment on the check's own principals
    and the (vpc_id, subnet_id) pair from _create_public_vpc."""
    return [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType",
         "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType",
         "Value": "t3.micro"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile",
         "Value": profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole",
         "Value": service_role},
        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType",
         "Value": "enhanced"},
        *_vpc_options(*network),
    ]


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


def _error_code_and_message(fn):
    """The AWS (Error.Code, Error.Message) a call raises; raises if the call succeeds."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None) or {}
        err = resp.get("Error") or {}
        assert err.get("Code"), f"the refusal carried no AWS error code: {type(exc).__name__}: {exc}"
        return err["Code"], err.get("Message")
    raise AssertionError(
        "the call SUCCEEDED where real AWS refuses it — an accepted input is a fidelity gap, "
        "not an error-code difference")


@tags("axis:rejection", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data", "cap:c1")
def run(ctx) -> None:
    """ValidateConfigurationSettings flags BatchSize=200 (Percentage, max 100) and UpdateEnvironment
    refuses it with the same message, leaving config and app untouched; an in-range value is
    accepted.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    nonce = ctx.unique_name("nonce-")
    tag = [{"Key": "sim2real", "Value": "eb-bad-option"}]
    cmd_ns = "aws:elasticbeanstalk:command"

    app = ctx.unique_name("sim2real-eb-opt2-app-")
    eb.create_application(ApplicationName=app, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"sim2real-eb/{app}/v1.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce), Tagging="sim2real=eb-bad-option")
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

    env = ctx.unique_name("sim2real-eb-opt2-env-")
    profile, role = _eb_iam(ctx)
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
                CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
                OptionSettings=_base_options(profile, role, _create_public_vpc(ctx)), Tags=tag)
    ready = _poll(lambda: _describe_env(eb, env),
                  lambda e: e is not None and e.get("Status") == "Ready",
                  timeout_s=1500, interval_s=2, what=f"environment {env} reaching Ready")
    url = f"http://{ready['CNAME']}/"
    control = _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1], timeout_s=600,
                          interval_s=2, what=f"{env} serving before the refused update")
    assert control[1].strip() == f"sim2real-nonce={nonce}", (
        f"the control half: the application must really be running; got {control!r}")

    def _cmd_settings():
        cfg = eb.describe_configuration_settings(ApplicationName=app, EnvironmentName=env)
        return {o["OptionName"]: o.get("Value")
                for o in cfg["ConfigurationSettings"][0]["OptionSettings"]
                if o.get("Namespace") == cmd_ns}

    before = _cmd_settings()
    # MinSize above MaxSize is not flagged on a single-instance environment; a BatchSize above
    # the documented Percentage maximum of 100 is.
    bad = [{"Namespace": cmd_ns, "OptionName": "BatchSizeType", "Value": "Percentage"},
           {"Namespace": cmd_ns, "OptionName": "BatchSize", "Value": "200"}]

    messages = eb.validate_configuration_settings(
        ApplicationName=app, EnvironmentName=env, OptionSettings=bad).get("Messages") or []
    errors = [m for m in messages if m.get("Severity") == "error"]
    assert len(errors) == 1, (
        f"the validator must report exactly one error for one out-of-range option; it returned "
        f"{messages!r}")
    flagged = errors[0]
    assert flagged["Namespace"] == cmd_ns and flagged["OptionName"] == "BatchSize", (
        f"the validator must attribute the error to the option that is wrong; it said "
        f"{flagged!r}")
    expected_validator_message = (
        "Invalid option value: '200' (Namespace: 'aws:elasticbeanstalk:command', OptionName: "
        "'BatchSize'): Value exceeds maximum allowed value: 100 for Percentage Batch Size Type.")
    assert flagged["Message"] == expected_validator_message, (
        f"the validator must name the published maximum it is enforcing; expected "
        f"{expected_validator_message!r}, its message was {flagged['Message']!r}")

    # Break exactly one thing: hand the mutator the input the validator just flagged.
    code, message = _error_code_and_message(
        lambda: eb.update_environment(EnvironmentName=env, OptionSettings=bad))
    assert code == "ConfigurationValidationException", (
        f"the mutator must refuse what the validator flagged, with the same validator's own "
        f"exception; got {code!r}: {message!r}")
    expected_message = f"Configuration validation exception: {expected_validator_message}"
    assert message == expected_message, (
        f"the refusal must carry the validator's exact message; expected {expected_message!r}, "
        f"got {message!r}")

    after = _cmd_settings()
    assert after == before, (
        f"a refused update must leave the live configuration byte-identical; the {cmd_ns} "
        f"settings were {before!r} and are now {after!r}")
    undisturbed = _describe_env(eb, env)
    assert undisturbed["Status"] == "Ready", (
        f"the refused update must not move the environment; it is now "
        f"{undisturbed['Status']!r}")
    again = _http_until(ctx, url, lambda r: r[0] == 200, timeout_s=300, interval_s=2,
                        what=f"{env} still serving after the refused update")
    assert again[1].strip() == f"sim2real-nonce={nonce}", (
        f"the rejected update must not disturb the running application; got {again!r}")

    # Positive control, same file, same call, the one thing put back inside its range.
    good = [{"Namespace": cmd_ns, "OptionName": "BatchSizeType", "Value": "Percentage"},
            {"Namespace": cmd_ns, "OptionName": "BatchSize", "Value": "50"}]
    clean = eb.validate_configuration_settings(
        ApplicationName=app, EnvironmentName=env, OptionSettings=good).get("Messages") or []
    assert not [m for m in clean if m.get("Severity") == "error"], (
        f"an in-range value must not be flagged; the validator said {clean!r}")
    upd = eb.update_environment(EnvironmentName=env, OptionSettings=good)
    assert upd["Status"] == "Updating", (
        f"the in-range update must be accepted and start updating, got {upd['Status']!r}")
    _poll(lambda: (_describe_env(eb, env) or {}).get("Status"), lambda s: s == "Ready",
          timeout_s=1500, interval_s=2, what=f"environment {env} settling after the good update")
    settled = _cmd_settings()
    assert settled["BatchSize"] == "50", (
        f"the accepted value must be reflected by DescribeConfigurationSettings; the {cmd_ns} "
        f"settings are {settled!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
