"""deep-ecs-guest-identity-task-role-is-the-guests-credential-source-and-identity."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-guest-identity-task-role-is-the-guests-credential-source-and-identity"

GROUP = "guest-identity"

SERVICES = ["ecs", "logs"]

#: An AWS-published image that ships boto3 (under /var/runtime), so the guest resolves
#: credentials through the SDK's own default provider chain exactly as customer code does.
_IMAGE = "public.ecr.aws/lambda/python:3.12"

#: The guest. It prints only NAMES of AWS_* variables and a sha256 of access-key ids -- never a
#: secret -- as one `TRJSON {...}` line, or `TRERR <traceback>` if anything raised.
_GUEST = r"""
import hashlib, json, os, sys, time, traceback, urllib.request
def sha(v):
    return hashlib.sha256(v.encode()).hexdigest()
out = {}
try:
    out["aws_env_names"] = sorted(k for k in os.environ if k.startswith("AWS_"))
    rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    out["relative_uri_present"] = bool(rel)
    if rel:
        with urllib.request.urlopen("http://169.254.170.2" + rel, timeout=10) as r:
            doc = json.loads(r.read())
        out["endpoint_role_arn"] = doc.get("RoleArn")
        out["endpoint_akid_sha"] = sha(doc.get("AccessKeyId", ""))
        out["endpoint_has_token"] = bool(doc.get("Token"))
    try:
        req = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                                     headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(req, timeout=3) as r:
            out["imds"] = "served:%d" % r.status
    except Exception as exc:
        out["imds"] = "unavailable:" + type(exc).__name__
    with urllib.request.urlopen(os.environ["ECS_CONTAINER_METADATA_URI_V4"] + "/task", timeout=10) as r:
        meta = json.loads(r.read())
    import boto3, botocore.exceptions
    sess = boto3.Session()
    creds = sess.get_credentials()
    out["chain_method"] = creds.method
    out["chain_akid_sha"] = sha(creds.get_frozen_credentials().access_key)
    ident = sess.client("sts").get_caller_identity()
    out["caller"] = {k: ident[k] for k in ("Arn", "Account", "UserId")}
    deadline = time.time() + 60  # IAM propagation of the task role's grant
    while True:
        try:
            got = sess.client("ecs").describe_tasks(cluster=meta["Cluster"], tasks=[meta["TaskARN"]])
            out["allowed"] = {"ok": True, "taskArns": [t["taskArn"] for t in got["tasks"]]}
            break
        except botocore.exceptions.ClientError as exc:
            out["allowed"] = {"ok": False, "code": exc.response["Error"]["Code"]}
            if out["allowed"]["code"] != "AccessDeniedException" or time.time() >= deadline:
                break
        time.sleep(2)
    try:
        sess.client("ecr").get_authorization_token()
        out["denied"] = {"ok": True}
    except botocore.exceptions.ClientError as exc:
        out["denied"] = {"ok": False, "code": exc.response["Error"]["Code"],
                         "message": exc.response["Error"].get("Message", "")}
    print("TRJSON " + json.dumps(out, separators=(",", ":")), flush=True)
except Exception:
    print("TRERR " + traceback.format_exc().replace("\n", " | "), flush=True)
time.sleep(900)
"""

_TASK_RUNNING_TIMEOUT_S = 600
_LOG_TIMEOUT_S = 480


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Inside a Fargate task the default credential chain resolves the task role from the
    container credentials endpoint, and AWS authorizes the guest as that role only: an action
    granted solely to the execution role is refused with AccessDeniedException."""
    ecs = ctx.client("ecs")
    net = _build_network(ctx, "trl")
    try:
        _body(ctx, ecs, net)
    finally:
        _settle(ctx, net)


def _body(ctx, ecs, net) -> None:
    account = ctx.client("sts").get_caller_identity()["Account"]
    log_group = _create_log_group(ctx)
    exec_role = _iam_role(ctx, "trl-exec", [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "ecr:GetAuthorizationToken"],
         "Resource": "*"}])
    task_role = _iam_role(ctx, "trl-task", [
        {"Effect": "Allow", "Action": ["ecs:DescribeTasks"], "Resource": "*"}])
    exec_name, task_name = exec_role.rsplit("/", 1)[-1], task_role.rsplit("/", 1)[-1]

    iam = ctx.client("iam")
    exec_doc = json.dumps(iam.get_role_policy(RoleName=exec_name, PolicyName="inline")["PolicyDocument"])
    task_doc = json.dumps(iam.get_role_policy(RoleName=task_name, PolicyName="inline")["PolicyDocument"])
    assert "ecr:GetAuthorizationToken" in exec_doc and "ecr:" not in task_doc, (
        f"the precondition for the rejection is not in place: exec={exec_doc} task={task_doc}"
    )

    cluster_arn = _create_cluster(ctx, net)
    family = ctx.unique_name("sim2real-deg-trl-")
    td = _register_task_def(ctx, family, [{
        "name": "guest",
        "image": _IMAGE,
        "essential": True,
        "entryPoint": ["python3", "-c", _GUEST],
        "environment": [
            {"name": "PYTHONPATH", "value": "/var/runtime"},
            {"name": "AWS_DEFAULT_REGION", "value": ctx.region},
            {"name": "AWS_STS_REGIONAL_ENDPOINTS", "value": "regional"},
        ],
        "logConfiguration": _awslogs(log_group, ctx.region),
    }], exec_role, task_role=task_role, cpu="256", memory="512")

    task_arn, _ = _launch_running(ctx, cluster_arn, td["taskDefinitionArn"], net)
    task_id = task_arn.rsplit("/", 1)[-1]

    stream = f"ecs/guest/{task_id}"
    lines = _poll(lambda: _log_messages(ctx, log_group, stream),
                  lambda ms: any(m.startswith(("TRJSON ", "TRERR ")) for m in ms),
                  _LOG_TIMEOUT_S, what=f"the guest's report in {stream}")
    errs = [m for m in lines if m.startswith("TRERR ")]
    assert not errs, f"the guest program raised: {errs[0][:3000]}"
    rep = json.loads([m for m in lines if m.startswith("TRJSON ")][-1][len("TRJSON "):])

    # --- the credential SOURCE is the container credentials endpoint ---------------------------
    names = rep["aws_env_names"]
    assert rep["relative_uri_present"] and "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" in names, (
        f"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is not set in the guest; AWS_* present: {names!r}"
    )
    assert "AWS_ACCESS_KEY_ID" not in names and "AWS_SECRET_ACCESS_KEY" not in names, (
        f"static keys were injected into the guest's environment: {names!r}"
    )
    assert rep.get("endpoint_role_arn") == task_role, (
        f"the container credentials endpoint serves RoleArn {rep.get('endpoint_role_arn')!r}; "
        f"the task role is {task_role!r} (execution role {exec_role!r})"
    )
    assert rep.get("endpoint_has_token"), "the endpoint served credentials with no session token"
    assert rep["chain_method"] == "container-role", (
        f"boto3's default chain resolved credentials via {rep['chain_method']!r}, not the "
        f"container credentials provider"
    )
    assert rep["chain_akid_sha"] == rep["endpoint_akid_sha"], (
        "the access key boto3 resolved is not the one the container credentials endpoint serves"
    )
    assert not str(rep.get("imds", "")).startswith("served:"), (
        f"the EC2 instance metadata service answered the Fargate guest: {rep['imds']!r}"
    )

    # --- the IDENTITY AWS authorizes is the task role ------------------------------------------
    caller = rep["caller"]
    want_arn = f"arn:aws:sts::{account}:assumed-role/{task_name}/{task_id}"
    assert caller["Account"] == account and caller["Arn"] == want_arn, (
        f"sts:GetCallerIdentity from inside the task returned {caller['Arn']!r} "
        f"(account {caller['Account']!r}); expected {want_arn!r}"
    )
    assert exec_name not in caller["Arn"], f"the guest is the execution role: {caller['Arn']!r}"

    # --- effect: the task role's grant works; effect-absent: the execution role's grant does not
    assert rep["allowed"] == {"ok": True, "taskArns": [task_arn]}, (
        f"ecs:DescribeTasks (granted to the task role) from inside the guest: {rep['allowed']!r}"
    )
    denied = rep["denied"]
    assert denied.get("ok") is False and denied.get("code") == "AccessDeniedException", (
        f"ecr:GetAuthorizationToken, granted ONLY to the execution role, was not refused with "
        f"AccessDeniedException: {denied!r}"
    )
    assert task_name in denied.get("message", "") and exec_name not in denied.get("message", ""), (
        f"the refusal does not name the task role as the denied principal: {denied!r}"
    )


# ===== helpers =====
# Own VPC + IGW + one public subnet + one security group, all created here (no default VPC).
# Cleanup is registered immediately after each create and ordered so LIFO runs:
# stop task -> deregister task def -> delete cluster -> delete SG -> delete subnet -> delete
# IGW -> delete VPC -> delete log group -> delete roles. The slow half (tasks reaching STOPPED,
# ENIs released) is waited for IN BAND by _settle, because the engine gives teardown 60 s.

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK[:200]}


def _ec2_tags(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name}] + [
        {"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags() -> list[dict]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


#: Error codes saying the resource does not exist: already deleted, or not created yet.
_GONE = ("ClusterNotFoundException", "ResourceNotFoundException", "NoSuchEntity",
         "Gateway.NotAttached")
#: Error codes of a delete refused while a dependency (a task ENI, a stopping task) is released.
_IN_USE = ("DependencyViolation", "ClusterContainsTasksException",
           "ClusterContainsServicesException", "ResourceInUseException")
_RELEASE_S = 120.0


def _unless_gone(fn, retry_s: float = 0.0):
    """fn(), or None when the target answers that the resource does not exist; within retry_s an
    in-use refusal is retried every 2 s; every other error raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in _GONE:
                return None
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll(probe, predicate, timeout_s, interval_s=5.0, what="condition"):
    """Bounded retry that RAISES on timeout. Never a bare sleep standing in for a wait."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _usable_zone(ec2) -> str:
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, "no available availability zone in this region"
    return zones[0]


def _build_network(ctx, label: str) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-deg-{label}-")
    net: dict = {"name": name, "subnet_cidr": "10.86.1.0/24", "tasks": []}
    vpc = ec2.create_vpc(CidrBlock="10.86.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _ec2_tags(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc), _RELEASE_S))
    net["vpc"] = vpc
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _ec2_tags(name)}])[
        "InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _unless_gone(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))
        _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw), _RELEASE_S)

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rts = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
    assert len(rts) == 1, f"a fresh VPC must have exactly one route table; got {rts!r}"
    ec2.create_route(RouteTableId=rts[0]["RouteTableId"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw)

    net["az"] = _usable_zone(ec2)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=net["subnet_cidr"],
                               AvailabilityZone=net["az"], TagSpecifications=[
                                   {"ResourceType": "subnet", "Tags": _ec2_tags(name)}])[
        "Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet), _RELEASE_S))
    net["subnet"] = subnet

    sg = ec2.create_security_group(
        GroupName=name, Description="sim2real deep-ecs-guest-identity task SG", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=sg), _RELEASE_S))
    net["sg"] = sg
    return net


def _drain_enis(ctx, subnet: str, timeout_s: float) -> None:
    ec2 = ctx.client("ec2")
    _poll(
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"],
        lambda enis: not enis, timeout_s, 2, what=f"subnet {subnet} releasing its task ENIs")


def _settle(ctx, net: dict) -> None:
    """In-band teardown of the slow half: stop every task and wait for the subnet's ENIs to be
    released before the registered deletes run; a task or ENI that outlasts the wait raises,
    carrying any failure in flight."""
    found = sys.exc_info()[1]
    try:
        ecs = ctx.client("ecs")
        tasks, cluster = list(net.get("tasks", [])), net.get("cluster")
        for t in tasks:
            _unless_gone(lambda t=t: ecs.stop_task(cluster=cluster, task=t,
                                                   reason="sim2real teardown"))
        if tasks:
            _poll(
                lambda: [x["lastStatus"] for x in ecs.describe_tasks(
                    cluster=cluster, tasks=tasks)["tasks"]],
                lambda ss: len(ss) == len(tasks) and all(x == "STOPPED" for x in ss), 300, 2,
                what="every task this check started reaching STOPPED")
        if net.get("subnet"):
            _drain_enis(ctx, net["subnet"], 300)
    except Exception as exc:
        raise AssertionError(
            (f"{found!r}; " if found else "") + f"teardown could not settle the tasks: {exc!r}"
        ) from exc


def _iam_role(ctx, kind: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-deg-{kind}-")
    arn = iam.create_role(
        RoleName=name, Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()])["Role"]["Arn"]

    def _drop():
        _unless_gone(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _unless_gone(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    _poll(lambda: _unless_gone(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
          lambda r: r is not None, 60, 2, what=f"role {name} inline policy readable")
    # IAM propagation has no observable condition: a task whose launch races it is relaunched by
    # _launch_running, and the guest retries its granted call on AccessDeniedException.
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-deg-lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _unless_gone(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(group: str, region: str) -> dict:
    return {"logDriver": "awslogs", "options": {
        "awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": "ecs"}}


def _create_cluster(ctx, net: dict) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-deg-cl-"),
                             tags=_ecs_tags())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.delete_cluster(cluster=arn), _RELEASE_S))
    net["cluster"] = arn
    return arn


def _register_task_def(ctx, family, containers, exec_role, task_role=None, cpu="256",
                       memory="512") -> dict:
    ecs = ctx.client("ecs")
    kwargs = dict(family=family, containerDefinitions=containers,
                  requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu=cpu,
                  memory=memory, executionRoleArn=exec_role, tags=_ecs_tags())
    if task_role:
        kwargs["taskRoleArn"] = task_role
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return td


def _run_task(ctx, cluster, td_arn, net, sgs=None, overrides=None) -> str:
    ecs = ctx.client("ecs")
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:  # InvalidInput: the account already holds ECS's linked role
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise
    kwargs = dict(cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                  tags=_ecs_tags(), networkConfiguration={"awsvpcConfiguration": {
                      "subnets": [net["subnet"]], "securityGroups": sgs or [net["sg"]],
                      "assignPublicIp": "ENABLED"}})
    if overrides:
        kwargs["overrides"] = overrides
    deadline = time.monotonic() + 120
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:  # a just-created role may not be assumable by ECS yet: retry to the deadline
        try:
            resp = ecs.run_task(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            text = str(exc).lower()
            if not ((code == "InvalidParameterException" and "role" in text) or (
                    code == "ClientException" and "unable to assume the role" in text)):
                raise
            assert time.monotonic() < deadline, "RunTask kept rejecting the freshly created roles"
        time.sleep(2)
    assert resp["failures"] == [], f"RunTask failures: {resp['failures']!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    net["tasks"].append(arn)
    return arn


def _launch_running(ctx, cluster, td_arn, net, timeout_s=120.0, **kw) -> tuple[str, dict]:
    """RunTask and await RUNNING, relaunching for up to timeout_s while the task fails to start
    before its container ran (a just-created execution role not yet usable by ECS)."""
    ecs = ctx.client("ecs")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        arn = _run_task(ctx, cluster, td_arn, net, **kw)
        task = _poll(lambda: (ecs.describe_tasks(cluster=cluster, tasks=[arn]).get("tasks")
                              or [{}])[0],
                     lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"),
                     _TASK_RUNNING_TIMEOUT_S, what=f"task {arn} reaching RUNNING")
        never_ran = all(c.get("exitCode") is None for c in task.get("containers", []))
        if task.get("stopCode") != "TaskFailedToStart" or not never_ran or (
                time.monotonic() >= deadline):
            return arn, _await_task(ctx, cluster, arn, "RUNNING", _TASK_RUNNING_TIMEOUT_S)
        time.sleep(2)


def _await_task(ctx, cluster, task_arn, status, timeout_s) -> dict:
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    task = _poll(probe, lambda t: t.get("lastStatus") in (status, "STOPPED"), timeout_s,
                 what=f"task {task_arn} reaching {status}")
    assert task["lastStatus"] == status, (
        f"task {task_arn} is {task['lastStatus']!r}, expected {status!r}: stopCode="
        f"{task.get('stopCode')!r} stoppedReason={task.get('stoppedReason')!r} containers="
        f"{[(c['name'], c.get('exitCode'), c.get('reason')) for c in task.get('containers', [])]!r}"
    )
    return task


def _eni_details(task: dict) -> dict:
    atts = [a for a in task.get("attachments", []) if a["type"] == "ElasticNetworkInterface"]
    assert len(atts) == 1, f"an awsvpc task has exactly one ENI attachment; got {atts!r}"
    return {d["name"]: d["value"] for d in atts[0]["details"]}


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    """Every event in the stream, paginated forward from the head ([] until it exists)."""
    logs = ctx.client("logs")
    msgs: list[str] = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = _unless_gone(lambda: logs.get_log_events(**kwargs))
        if page is None:
            return msgs
        events = page.get("events", [])
        msgs += [e.get("message", "") for e in events]
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return msgs
        token = nxt


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
