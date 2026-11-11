"""eb-describe-instances-health-reports-the-environments-real-instances."""
from __future__ import annotations

import datetime
import http.client
import io
import json
import re
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


CHECK = "eb-describe-instances-health-reports-the-environments-real-instances"
GROUP = "environment-data-plane"
SERVICES = ["elasticbeanstalk"]

#: Lets a Ready environment with nothing listening on the CNAME fail as a missing data plane.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals that mean "the IAM principal this check just created is not visible
#: to Elastic Beanstalk yet". Retried, bounded, in `_create_env`; anything else re-raises.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: A healthy (Ok/Green) instance's Causes are not always empty: right after a deployment they carry
#: this informational status, whose two durations cannot exceed the time since CreateEnvironment.
_DEPLOY_CAUSE_RE = re.compile(
    r"^Application deployment completed (\d+) seconds? ago and took (\d+) seconds?\.$")

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


def _create_public_vpc(ctx):
    """Create a VPC with one public subnet so the launch never depends on the default VPC.

    Cleanup is registered first, so it runs after the environment's."""
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


def _delete_vpc(ec2, vpc_id, timeout_s=600.0, interval_s=15.0):
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


def _base_options(profile, service_role, network, single_instance=True):
    """The minimum option set for an environment on the given principals and network.

    `network` is the (vpc_id, subnet_id) pair from _create_public_vpc; `t3.micro` is deliberate.
    """
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
        *_vpc_options(*network),
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DescribeInstancesHealth lists exactly the instances DescribeEnvironmentResources reports,
    each Ok/Green with the deployed VersionLabel, a bounded LaunchedAt and full attributes, and
    DescribeEnvironmentHealth counts the same instances as Ok.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeInstancesHealth.html
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    marker = "eb-instances-health"
    nonce = ctx.unique_name("nonce-")

    app = _new_application(ctx, eb, "sim2real-eb-ih-app-", marker)
    label, _bucket, _key = _publish_version(ctx, eb, s3, app, marker, nonce)

    env = ctx.unique_name("sim2real-eb-ih-env-")
    profile, role = _eb_iam(ctx, marker)
    create_started = datetime.datetime.now(datetime.timezone.utc)
    _create_env(
        ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
        CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
        OptionSettings=_base_options(profile, role, _create_public_vpc(ctx)),
        Tags=[{"Key": "sim2real", "Value": marker}])
    ready = _ready(eb, env, timeout_s=_budget_s(ctx, 1500.0), ctx=ctx)
    url = f"http://{ready['CNAME']}/"
    _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1], timeout_s=_budget_s(ctx, 600.0),
                interval_s=2,
                what=f"{env} serving its own nonce, so its instance is genuinely in service")

    resources = eb.describe_environment_resources(EnvironmentName=env)["EnvironmentResources"]
    real_instances = {i["Id"] for i in resources["Instances"]}
    assert real_instances, (
        f"DescribeEnvironmentResources must report the instances of an environment that is "
        f"answering HTTP; it reported {resources!r}")

    def _health():
        return eb.describe_instances_health(
            EnvironmentName=env, AttributeNames=["All"]).get("InstanceHealthList") or []

    def _settled(lst):
        return {i.get("InstanceId") for i in lst} == real_instances and all(
            i.get("HealthStatus") == "Ok" and i.get("Color") == "Green"
            and (i.get("Deployment") or {}).get("Status") == "Deployed" for i in lst)

    # Enhanced health fills the per-instance view, and moves it to Ok, a little after the
    # environment settles.
    listed = _poll(_health, _settled,
                   timeout_s=_budget_s(ctx, 600.0), interval_s=1,
                   what=(f"DescribeInstancesHealth reporting exactly the instances "
                         f"{real_instances!r} that DescribeEnvironmentResources reports for "
                         f"{env}, each Ok/Green with its deployment Deployed"), ctx=ctx)
    reported = {i.get("InstanceId") for i in listed}
    assert reported == real_instances, (
        f"the two independent reads must agree about which instances exist: "
        f"DescribeInstancesHealth reported {reported!r} and DescribeEnvironmentResources reported "
        f"{real_instances!r}")

    created_at = ready["DateCreated"]
    now = datetime.datetime.now(datetime.timezone.utc)
    for inst in listed:
        iid = inst.get("InstanceId")
        assert inst.get("HealthStatus") == "Ok", (
            f"instance {iid!r} of a freshly deployed, HTTP-serving environment must report "
            f"HealthStatus Ok, got {inst.get('HealthStatus')!r} with causes {inst.get('Causes')!r}")
        assert inst.get("Color") == "Green", (
            f"an Ok instance must be coloured Green; instance {iid!r} reported "
            f"{inst.get('Color')!r}")
        causes = inst.get("Causes") or []
        elapsed_since_create_s = (now - create_started).total_seconds()
        for cause in causes:
            match = _DEPLOY_CAUSE_RE.match(cause)
            assert match, (
                f"a healthy (Ok/Green) instance {iid!r} reported a Cause that is not the known "
                f"informational deployment-completion status: {cause!r} (full Causes {causes!r})")
            ago_s, took_s = int(match.group(1)), int(match.group(2))
            assert 0 <= ago_s <= elapsed_since_create_s, (
                f"instance {iid!r} Cause {cause!r} claims the deployment completed {ago_s}s ago, "
                f"which must fall within [0, {elapsed_since_create_s:.0f}]s — the time elapsed "
                f"since this check called CreateEnvironment")
            assert 0 <= took_s <= elapsed_since_create_s, (
                f"instance {iid!r} Cause {cause!r} claims the deployment took {took_s}s, which "
                f"cannot exceed the {elapsed_since_create_s:.0f}s elapsed since this check called "
                f"CreateEnvironment")
        deployment = inst.get("Deployment") or {}
        assert deployment.get("VersionLabel") == label, (
            f"the per-instance health view must know which application version is running on "
            f"instance {iid!r}: it reported VersionLabel {deployment.get('VersionLabel')!r}, "
            f"expected the deployed {label!r} (full Deployment block {deployment!r})")
        assert deployment.get("Status") == "Deployed", (
            f"the deployment on instance {iid!r} completed — the instance is serving HTTP — so "
            f"its Deployment Status must be Deployed, got {deployment.get('Status')!r} in "
            f"{deployment!r}")
        launched = inst.get("LaunchedAt")
        assert launched is not None, (
            f"instance {iid!r} must report when it was launched; the entry was {inst!r}")
        # The instance cannot predate the environment, nor postdate now.
        assert created_at <= launched <= now, (
            f"instance {iid!r} reports LaunchedAt {launched!r}, which is not between the "
            f"environment's own DateCreated {created_at!r} and its DateUpdated {now!r}")
        assert isinstance(inst.get("ApplicationMetrics"), dict), (
            f"AttributeNames=['All'] must populate ApplicationMetrics for instance {iid!r}; the "
            f"entry was {inst!r}")
        assert isinstance(inst.get("System"), dict), (
            f"AttributeNames=['All'] must populate System for instance {iid!r}; the entry was "
            f"{inst!r}")

    # The environment-level health view must agree that every instance it counts is Ok.
    env_health = _poll(
        lambda: eb.describe_environment_health(EnvironmentName=env, AttributeNames=["All"]),
        lambda h: (h.get("InstancesHealth") or {}).get("Ok") == len(real_instances),
        timeout_s=_budget_s(ctx, 120.0), interval_s=1,
        what=f"DescribeEnvironmentHealth counting the {len(real_instances)} instance(s) as Ok",
        ctx=ctx)
    counts = env_health.get("InstancesHealth") or {}
    assert counts.get("Ok") == len(real_instances), (
        f"DescribeEnvironmentHealth must count exactly the {len(real_instances)} Ok instance(s) "
        f"that DescribeInstancesHealth described; it reported InstancesHealth={counts!r}")
    assert sum(v for v in counts.values() if isinstance(v, int)) == len(real_instances), (
        f"the environment health counters must add up to the real instance count "
        f"{len(real_instances)}; they were {counts!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
