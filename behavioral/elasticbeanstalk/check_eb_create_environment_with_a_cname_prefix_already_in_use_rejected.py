"""eb-create-environment-with-a-cname-prefix-already-in-use-rejected."""
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



CHECK = "eb-create-environment-with-a-cname-prefix-already-in-use-rejected"
GROUP = 'errors'
SERVICES = ['elasticbeanstalk']

#: Prefixes the failure raised when an environment reports Ready but nothing answers on its
#: CNAME, so that outcome is classified as a failure rather than an environment error.
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

    Returns (instance_profile, service_role).
    """
    iam = ctx.client("iam")

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": "eb-dup-cname"}])
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
    # IAM exposes no condition that reports a principal has become usable by another service; the
    # bounded retry in _create_env below already absorbs this propagation delay, so no sleep here.
    return profile, svc_role


def _base_options(profile, service_role, vpc):
    opts = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType",
         "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType",
         "Value": "t3.micro"},
        *_vpc_options(*vpc),
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


def _create_public_vpc(ctx):
    """Create a VPC with one public subnet for the environment, so the launch never depends on
    the account's default VPC. Cleanup is registered first, so it runs after the environment's."""
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



def _env_names(eb):
    """Every non-deleted environment name, paginated.

    IncludeDeleted=False is explicit because AWS defaults it to true and returns Terminated ones."""
    out, token = [], None
    while True:
        kw = {"MaxRecords": 100, "IncludeDeleted": False}
        if token:
            kw["NextToken"] = token
        r = eb.describe_environments(**kw)
        out.extend(e["EnvironmentName"] for e in r.get("Environments") or [])
        token = r.get("NextToken")
        if not token:
            return out


def _error(fn):
    """The AWS (code, message) a call raises; an unexpected success raises AssertionError."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None) or {}
        code = (resp.get("Error") or {}).get("Code")
        assert code, f"the refusal carried no AWS error code: {type(exc).__name__}: {exc}"
        return code, (resp.get("Error") or {}).get("Message")
    raise AssertionError(
        "the call SUCCEEDED where real AWS refuses it — an accepted input is a fidelity gap, "
        "not an error-code difference")


@tags("axis:rejection", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A CNAMEPrefix a live, serving environment holds is refused with InvalidParameterValue, no
    second environment appears, the live app is undisturbed, and a fresh prefix is accepted."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    nonce = ctx.unique_name("nonce-")
    tag = [{"Key": "sim2real", "Value": "eb-dup-cname"}]

    app = ctx.unique_name("sim2real-eb-dup-app-")
    eb.create_application(ApplicationName=app, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"sim2real-eb/{app}/v1.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce), Tagging="sim2real=eb-dup-cname")
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

    stack = _solution_stack(eb)
    vpc = _create_public_vpc(ctx)
    profile, role = _eb_iam(ctx)
    env_a = ctx.unique_name("sim2real-eb-dup-a-")
    prefix = env_a
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env_a, VersionLabel=label,
                CNAMEPrefix=prefix, SolutionStackName=stack,
                OptionSettings=_base_options(profile, role, vpc), Tags=tag)
    ready = _poll(lambda: _describe_env(eb, env_a),
                  lambda e: e is not None and e.get("Status") == "Ready",
                  timeout_s=1500, interval_s=2, what=f"environment {env_a} reaching Ready")
    cname = ready["CNAME"]
    live = _http_until(ctx, f"http://{cname}/", lambda r: r[0] == 200 and nonce in r[1],
                       timeout_s=600, interval_s=2,
                       what=f"{env_a} serving its nonce, proving the prefix is really in use")
    assert live[1].strip() == f"sim2real-nonce={nonce}", (
        f"the prefix must be held by a genuinely running application; got {live!r}")

    # Break exactly one thing: the same prefix, everything else valid.
    env_b = ctx.unique_name("sim2real-eb-dup-b-")
    code, message = _error(lambda: eb.create_environment(
        ApplicationName=app, EnvironmentName=env_b, VersionLabel=label, CNAMEPrefix=prefix,
        SolutionStackName=stack, OptionSettings=_base_options(profile, role, vpc), Tags=tag))
    assert code == "InvalidParameterValue", (
        f"reusing a live environment's CNAMEPrefix must be refused with InvalidParameterValue, "
        f"got {code!r} ({message!r})")
    expected = f"DNS name ({cname}) is not available."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_held = eb.check_dns_availability(CNAMEPrefix=prefix)
    assert still_held["Available"] is False, (
        f"the prefix really is the reason for the refusal: CheckDNSAvailability must report "
        f"Available False for {prefix!r}, got {still_held!r}")

    names = _env_names(eb)
    assert env_b not in names, (
        f"the refused create must leave no environment behind; {env_b!r} appeared among "
        f"{len(names)} DescribeEnvironments names")

    undisturbed = _describe_env(eb, env_a)
    assert undisturbed["Status"] == "Ready" and undisturbed["Health"] == "Green", (
        f"the failed create must not disturb the live environment; {env_a} is now "
        f"{undisturbed['Status']!r}/{undisturbed['Health']!r}")
    again = _http_until(ctx, f"http://{cname}/", lambda r: r[0] == 200, timeout_s=300, interval_s=2,
                        what=f"{env_a} still serving after the refused create")
    assert again[1].strip() == f"sim2real-nonce={nonce}", (
        f"the live application must be byte-identical after the refusal; got {again!r}")

    # Positive control, same file, same call, one thing changed back.
    fresh = ctx.unique_name("sim2real-eb-dup-c-")
    ok = _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env_b, VersionLabel=label,
                     CNAMEPrefix=fresh, SolutionStackName=stack,
                     OptionSettings=_base_options(profile, role, vpc), Tags=tag)
    assert ok["EnvironmentName"] == env_b, (
        f"the identical create with an unused prefix must be accepted for {env_b!r}, got {ok!r}")
    assert ok["Status"] == "Launching", (
        f"the identical create with an unused prefix must be accepted and start Launching, got "
        f"{ok['Status']!r}")
    _assert_cname_takes(ctx, ok.get("CNAME"), fresh, "the accepted create must take the fresh prefix")

    # Terminal read is independent of the mutating CreateEnvironment call: the fresh prefix is now
    # really claimed, and the environment settles to Ready holding it, through two different
    # operations.
    claimed = eb.check_dns_availability(CNAMEPrefix=fresh)
    assert claimed["Available"] is False, (
        f"the fresh prefix must now be claimed by {env_b}: CheckDNSAvailability must report "
        f"Available False for {fresh!r}, got {claimed!r}")
    seen = _poll(lambda: _describe_env(eb, env_b),
                 lambda e: e is not None and e.get("Status") in ("Ready", "Terminated"),
                 timeout_s=1500, interval_s=2, what=f"environment {env_b} reaching Ready")
    assert seen["Status"] == "Ready", f"the accepted create must settle to Ready; got {seen!r}"
    _assert_cname_takes(ctx, seen.get("CNAME"), fresh,
                        "the settled environment must hold the fresh prefix")


def _assert_cname_takes(ctx, cname, prefix, what):
    """An environment CNAME is ``<prefix>.<region>.<service domain>``: on AWS its prefix, region and
    ``elasticbeanstalk`` labels are graded; a host the target publishes as its own is graded by form."""
    assert isinstance(cname, str) and cname, f"{what}: expected a CNAME, got {cname!r}"
    p = ctx.published_url_mismatch(f"http://{cname}", labels=(prefix, ctx.region, "elasticbeanstalk"))
    assert not p, f"{what}: {p}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
