"""eb-terminated-environment-stops-serving-and-frees-its-cname-prefix."""
from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags  # noqa: F401


CHECK = "eb-terminated-environment-stops-serving-and-frees-its-cname-prefix"
GROUP = 'environment-lifecycle'
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


def _ssl_context(verify):
    """An SSL context honouring ``ctx.http_verify``: a CA bundle path, True, or False."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_get(url: str, verify=True, timeout: float = 20.0):
    """(status, body) for a plain HTTP GET; an HTTP error status is a result, not an exception."""
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-eb-behavioral"})
    context = _ssl_context(verify) if url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _http_until(url: str, pred, *, verify, timeout_s: float, interval_s: float = 2.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds.

    A connection failure after the budget is a FAILURE, never a skip: an environment the control
    plane calls Ready and nobody can reach is the defect this check exists to find.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = _http_get(url, verify)
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

    Returns (instance_profile, service_role). Any IAM failure raises: an environment launched on the
    service's default principals is a different subject.
    """
    iam = ctx.client("iam")

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": "eb-terminate-stops"}])
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
    # bounded CreateEnvironment retry below over the propagation refusal covers that window.
    return profile, svc_role


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


def _base_options(profile, service_role, network):
    """The minimum option set for a gradeable environment, on principals and a network the check
    created. `network` is the (vpc_id, subnet_id) pair from _create_public_vpc, so the launch never
    depends on the account's default VPC.

    `t3.micro` is a deliberate literal: it is the instance type, i.e. the subject of the request,
    not an account-varying quota. Nothing here pins an account id or a region.
    """
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


def _env_names(eb):
    """Every non-deleted environment name, paginated: the account may hold many other environments.

    IncludeDeleted=False is passed EXPLICITLY because real AWS defaults it to true: omitting it
    returns Terminated environments too, so "absent from DescribeEnvironments" is only a
    meaningful assertion with the flag set."""
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


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Terminating an environment really stops the application and gives the CNAME prefix back.

    CheckDNSAvailability reports the prefix unavailable while the application answers with its
    nonce, and available again once the terminated environment stops serving it.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    nonce = ctx.unique_name("nonce-")
    tag = [{"Key": "sim2real", "Value": "eb-terminate-stops"}]

    app = ctx.unique_name("sim2real-eb-term-app-")
    eb.create_application(ApplicationName=app, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"sim2real-eb/{app}/v1.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce),
                  Tagging="sim2real=eb-terminate-stops")
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

    env = ctx.unique_name("sim2real-eb-term-env-")
    profile, role = _eb_iam(ctx)
    _create_env(ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
                CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
                OptionSettings=_base_options(profile, role, _create_public_vpc(ctx)), Tags=tag)
    ready = _poll(lambda: _describe_env(eb, env),
                  lambda e: e is not None and e.get("Status") == "Ready",
                  timeout_s=1500, interval_s=2, what=f"environment {env} reaching Ready")
    cname = ready["CNAME"]
    # the environment's CNAME is a published data-plane host serving plain HTTP on port 80
    url = ctx.endpoint_url(f"http://{cname}") + "/"

    live = _http_until(url, lambda r: r[0] == 200 and nonce in r[1], verify=ctx.http_verify, timeout_s=600,
                       interval_s=2, what=f"{env} serving its nonce before termination")
    assert live[1].strip() == f"sim2real-nonce={nonce}", (
        f"the control half: the application must really be serving before it is torn down; got "
        f"{live!r}")
    held = eb.check_dns_availability(CNAMEPrefix=env)
    assert held["Available"] is False, (
        f"a prefix held by a live environment must report Available False; CheckDNSAvailability "
        f"returned {held.get('Available')!r} for {env!r} while {cname!r} was serving")

    term = eb.terminate_environment(EnvironmentName=env)
    assert term["Status"] in ("Terminating", "Terminated"), (
        f"TerminateEnvironment must start the environment's termination, got "
        f"{term['Status']!r}")
    gone = _poll(lambda: _describe_env(eb, env),
                 lambda e: e is not None and e.get("Status") == "Terminated",
                 timeout_s=1200, interval_s=2, what=f"environment {env} reaching Terminated")
    assert gone["Status"] == "Terminated", (
        f"the settled status must be exactly Terminated, got {gone['Status']!r}")

    # The assertion is on the nonce's ABSENCE, not on a particular failure mode: AWS may leave a
    # parked page, refuse the connection, or fail to resolve, and all three are "stopped serving".
    dead = _http_until(url, lambda r: nonce not in str(r[1]), verify=ctx.http_verify, timeout_s=900, interval_s=2,
                       what=f"{cname!r} stopping serving nonce {nonce!r} after termination")
    assert nonce not in str(dead[1]), (
        f"a terminated environment must stop serving its application; {cname!r} still returned "
        f"{dead!r}")

    freed = _poll(lambda: eb.check_dns_availability(CNAMEPrefix=env),
                  lambda d: d["Available"] is True, timeout_s=900, interval_s=2,
                  what=f"the CNAME prefix {env!r} becoming available again")
    assert freed["Available"] is True, (
        f"terminating the environment must release its prefix reservation; "
        f"CheckDNSAvailability returned {freed!r}")
    # Measured on real AWS: FullyQualifiedCNAME is returned only on the AVAILABLE answer — the
    # held answer above is a bare {"Available": false}. Binding the freed answer to the same
    # hostname the environment had is what makes the release assertion about THIS prefix.
    assert freed["FullyQualifiedCNAME"] == cname, (
        f"the released prefix must resolve to the hostname the environment held; "
        f"CheckDNSAvailability named {freed.get('FullyQualifiedCNAME')!r}, the environment had "
        f"{cname!r}")

    names = _env_names(eb)
    assert env not in names, (
        f"a terminated environment must be absent from DescribeEnvironments without "
        f"IncludeDeleted; {env!r} was still among {len(names)} names")

    # A terminated environment is unusable: a mutation on it is refused, naming it.
    try:
        result = eb.update_environment(EnvironmentName=env, Description="post-terminate")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
    else:
        raise AssertionError(
            f"UpdateEnvironment on the terminated environment must be refused, it SUCCEEDED: {result!r}")
    assert err.get("Code") == "InvalidParameterValue", (
        f"UpdateEnvironment on the terminated environment: expected InvalidParameterValue, got "
        f"{err.get('Code')!r}")
    assert status == 400, f"UpdateEnvironment on the terminated environment: expected HTTP 400, got {status}"
    expected_message = f"Environment not found with Name: {env} in account '{ctx.account}'"
    assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
