"""eb-ebextensions-config-files-really-run-on-the-instance."""
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


CHECK = "eb-ebextensions-config-files-really-run-on-the-instance"
GROUP = "environment-data-plane"
SERVICES = ["elasticbeanstalk"]

# Helpers: an absent IAM prerequisite raises, IAM propagation is waited out by the bounded
# `_create_env` retry, and errors are caught as `ClientError` with an explicit code allowlist.

#: Lets a Ready environment with nothing listening on the CNAME fail as a missing data plane.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals that mean "the IAM principal this check just created is not visible
#: to Elastic Beanstalk yet". Retried, bounded, in `_create_env`; anything else re-raises.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: The application the check deploys. stdlib only, so the bundle needs no
#: dependency install and the served bytes are decided by the check rather than by a platform
#: sample app: every HTTP assertion is then an identity law over a nonce the check minted.
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

    ``extra`` adds arbitrary members (a `.ebextensions/*.config`, a static asset) so a check can
    ship the artefact whose EXECUTION it wants to observe.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Procfile", "web: python3 -u server.py\n")
        z.writestr("server.py", "NONCE = " + repr(nonce) + "\n" + _SERVER_PY)
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return buf.getvalue()


def _poll(probe, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll ``probe()`` until ``pred`` holds; raise AssertionError quoting the last value.

    Raises rather than returning its last value, so a truncated wait can never be read as a
    satisfied condition.
    """
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
    """(status, body) where a transport failure becomes the status ``"<no-response>"``.

    Used where UNREACHABILITY is the measurement rather than an error: sampling a CNAME across a
    deployment has to record "the load balancer had no healthy target" as a data point.
    """
    try:
        return _http_get(ctx, url, timeout=timeout)
    except (OSError, http.client.HTTPException) as exc:
        # Narrow on purpose: a refused connection, a reset and a truncated status line are the
        # measurement. Anything else (a bug in this check) still propagates.
        return "<no-response>", f"{type(exc).__name__}: {exc}"


def _http_until(ctx, url: str, pred, *, timeout_s: float, interval_s: float = 2.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds.

    A connection failure after the budget is a FAILURE, never a skip: an environment the control
    plane calls Ready and nobody can reach is the defect these checks exist to find.
    """
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

    Python is chosen because the platform's streamed log set for it is documented
    (/var/log/web.stdout.log carries the app's stdout) and because the bundle is stdlib-only.
    """
    stacks = eb.list_available_solution_stacks().get("SolutionStacks") or []
    py = [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
    assert py, (
        f"this check needs an Amazon Linux 2023 Python solution stack; "
        f"ListAvailableSolutionStacks offered none, returning {stacks[:12]!r}")
    return py[0]


def _eb_iam(ctx, marker: str, extra_instance_policies=()):
    """The instance profile + service role an environment needs, with LIFO teardown.

    If IAM is unreachable this raises: an environment launched without an instance profile is a
    different subject.
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


def _base_options(profile, service_role, network, single_instance=True):
    """The minimum option set for a gradeable environment, on principals and a network the check
    created. `network` is the (vpc_id, subnet_id) pair from _create_public_vpc, so the launch never
    depends on the account's default VPC.

    `t3.micro` is a deliberate literal: it is the instance type, i.e. the subject of the request,
    not an account-varying quota. Nothing here pins an account id or a region.
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

    IAM exposes no condition reporting that a principal has become usable by another service, so
    the retry — bounded, with a deadline, which RAISES the original refusal when it expires — is
    the control that replaces a sleep.
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
    """Terminate and poll to Terminated. Registered via ctx.on_cleanup, so it runs LIFO.

    This teardown routinely runs 180-420 s; cutting it off leaks a live EC2 instance and an
    Auto Scaling group.
    """
    terminate_deadline_s = 600.0
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
          timeout_s=terminate_deadline_s, interval_s=2,
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
    # Compared case-folded on purpose: real AWS answers "PROCESSING"/"PROCESSED" while the Smithy
    # model declares Processing/Processed, and casing is the wire fixtures' business, not depth.
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
    """Wait for the environment to settle Ready. The terminal set excludes every failure value, so
    a poll cannot terminate on `Terminated` or `Terminating`."""
    ready_deadline_s = 1500.0
    env = _poll(lambda: _describe_env(eb, env_name),
                lambda e: e is not None and e.get("Status") == "Ready",
                timeout_s=ready_deadline_s, interval_s=2,
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


def _assert_cname_takes(ctx, cname, prefix, what):
    """An environment CNAME is ``<prefix>.<region>.<service domain>``: on AWS its prefix, region and
    ``elasticbeanstalk`` labels are graded; a host the target publishes as its own is graded by form."""
    assert isinstance(cname, str) and cname, f"{what}: expected a CNAME, got {cname!r}"
    p = ctx.published_url_mismatch(f"http://{cname}", labels=(prefix, ctx.region, "elasticbeanstalk"))
    assert not p, f"{what}: {p}"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`.ebextensions` in the source bundle really EXECUTES on the environment's instances.

    A `files:` entry and a `container_commands:` side effect exist on the instance with the minted
    content, while a path the config never mentions answers 404.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    marker = "eb-ebextensions-exec"
    nonce = ctx.unique_name("nonce-")
    files_token = ctx.unique_name("files-token-")
    cmd_token = ctx.unique_name("cmd-token-")
    files_path = "/tmp/sim2real-ebextensions-files.txt"
    cmd_path = "/tmp/sim2real-ebextensions-command.txt"
    # A path no section of the config mentions. It is the negative control for the reader route.
    absent_path = "/tmp/sim2real-ebextensions-never-written.txt"

    config = (
        "files:\n"
        f'  "{files_path}":\n'
        '    mode: "000644"\n'
        "    owner: root\n"
        "    group: root\n"
        "    content: |\n"
        f"      {files_token}\n"
        "container_commands:\n"
        "  01_sim2real_marker:\n"
        f'    command: "printf %s {cmd_token} > {cmd_path}"\n'
    )

    app = _new_application(ctx, eb, "sim2real-eb-ebx-app-", marker)
    label, _bucket, _key = _publish_version(
        ctx, eb, s3, app, marker, nonce,
        extra={".ebextensions/sim2real.config": config})

    env = ctx.unique_name("sim2real-eb-ebx-env-")
    profile, role = _eb_iam(ctx, marker)
    created = _create_env(
        ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
        CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
        OptionSettings=_base_options(profile, role, _create_public_vpc(ctx)),
        Tags=[{"Key": "sim2real", "Value": marker}])
    assert created["Status"] == "Launching", (
        f"a newly created environment must start Launching, got {created['Status']!r}")

    ready = _ready(eb, env)
    cname = ready.get("CNAME") or ""
    _assert_cname_takes(ctx, cname, env,
                        "DescribeEnvironments must report the CNAME the prefix minted")
    url = f"http://{cname}/"

    _http_until(ctx, url, lambda r: r[0] == 200 and nonce in r[1], timeout_s=600.0, interval_s=2,
                what=f"the application deployed to {env} answering with its own nonce {nonce!r}")

    # --- Leg 3 FIRST: the reader route can say no. If this returns 200 the instrument is broken
    # --- and the two 200s below could not fail.
    missing = _http_get(ctx, f"{url}sim2real/file?{absent_path}")
    assert missing[0] == 404, (
        f"the on-instance file reader must 404 for a path .ebextensions never wrote, otherwise a "
        f"200 for the written paths proves nothing; asking for {absent_path!r} returned {missing!r}")

    # --- Leg 1: the `files:` section wrote a real file with exactly the content from the config. ---
    got_files = _http_until(ctx,
        f"{url}sim2real/file?{files_path}", lambda r: r[0] == 200,
        timeout_s=300.0, interval_s=2,
        what=(f"the file the .ebextensions `files:` section declares at {files_path!r} becoming "
              f"readable on the instance"))
    assert got_files[1].strip() == files_token, (
        f"the `files:` section must write exactly the content declared in the config; the instance "
        f"returned {got_files[1]!r} for {files_path!r}, expected {files_token!r}")

    # --- Leg 2: the `container_commands:` section really executed a shell command. ---
    got_cmd = _http_until(ctx,
        f"{url}sim2real/file?{cmd_path}", lambda r: r[0] == 200,
        timeout_s=300.0, interval_s=2,
        what=(f"the side effect of the .ebextensions container_command at {cmd_path!r} becoming "
              f"readable on the instance"))
    assert got_cmd[1].strip() == cmd_token, (
        f"the container_command must have run and written its token; the instance returned "
        f"{got_cmd[1]!r} for {cmd_path!r}, expected {cmd_token!r}")

    # --- The two artefacts must be distinguishable, so a target that serves one canned body for
    # --- every path fails even though both reads returned 200.
    assert got_files[1].strip() != got_cmd[1].strip(), (
        f"the `files:` content and the container_command output must differ; both paths returned "
        f"{got_files[1]!r}, which means the reader is serving one canned body")

    # --- Terminal read: an independent HTTP read at the instance, through a route that reads the
    # --- real filesystem, and the negative control re-checked AFTER both positives so a target
    # --- cannot have started answering 200 to everything in between.
    still_missing = _http_get(ctx, f"{url}sim2real/file?{absent_path}")
    assert still_missing[0] == 404, (
        f"the never-written path must still 404 after both files were read; got "
        f"{still_missing!r} for {absent_path!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
