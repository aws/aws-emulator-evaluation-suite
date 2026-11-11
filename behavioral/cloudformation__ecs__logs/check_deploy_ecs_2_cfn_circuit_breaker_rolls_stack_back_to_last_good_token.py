"""deploy-ecs-2-cfn-circuit-breaker-rolls-stack-back-to-last-good-token."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-2-cfn-circuit-breaker-rolls-stack-back-to-last-good-token"
GROUP = "deploy-cfn-ecs-rollback"
SERVICES = ["cloudformation", "ecs", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-managed Fargate service with circuit breaker Enable+Rollback rolls forward to a new
    task definition revision (token B in its logs), then rolls back from an exit-1 revision to the
    token-B revision at both the ECS and stack layers, and the stack deletes cleanly.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    t0 = time.monotonic()
    deadline = t0 + _TOTAL_BUDGET_S

    def _left(cap, reserve=_DELETE_TIMEOUT_S):
        return max(30.0, min(cap, deadline - reserve - time.monotonic()))

    # The breaker trips after a minimum of three failed tasks at desiredCount 1, so only
    # failureCount >= 1 is asserted and never an exact count or a rollback deadline.
    _ensure_ecs_slr(ctx)

    stack = ctx.unique_name(_PREFIX + "stk-")
    cluster = ctx.unique_name(_PREFIX + "cl-")
    service = ctx.unique_name(_PREFIX + "svc-")
    family = ctx.unique_name(_PREFIX + "td-")
    log_group = ctx.unique_name(_PREFIX + "lg-")
    token_a = ctx.unique_name("tokA-")
    token_b = ctx.unique_name("tokB-")
    token_c = ctx.unique_name("tokC-")
    zone = _usable_zone(ctx)

    def params(token, script):
        return [{"ParameterKey": k, "ParameterValue": v} for k, v in (
            ("ClusterName", cluster), ("ServiceName", service), ("Family", family),
            ("LogGroupName", log_group), ("Zone", zone), ("Token", token), ("Script", script))]

    state = {"deleted": False}

    def _teardown():
        if state["deleted"]:
            return
        cfn.delete_stack(StackName=stack)
        _wait_stack(cfn, stack, {"DELETE_COMPLETE"}, timeout_s=_DELETE_TIMEOUT_S)
        state["deleted"] = True

    # Registered BEFORE the create: a create that fails part-way still leaves a stack to delete.
    _record_stack_id = _task_definition_teardown(ctx, stack)
    ctx.on_cleanup(_teardown)
    ctx.on_cleanup(_record_stack_id)
    try:
        # ---------------- phase 1: create ----------------
        cfn.create_stack(StackName=stack, TemplateBody=json.dumps(_TEMPLATE),
                         Parameters=params(token_a, _GOOD_SCRIPT), Capabilities=["CAPABILITY_IAM"],
                         Tags=[{"Key": "sim2real", "Value": CHECK}])
        created = _wait_stack(cfn, stack, {"CREATE_COMPLETE"}, timeout_s=_left(_CREATE_TIMEOUT_S))
        out = {o["OutputKey"]: o["OutputValue"] for o in created.get("Outputs", [])}
        td_a = out["TaskDefinitionArn"]
        cluster_arn = out["ClusterArn"]
        task_a = _sole_running_task(ecs, cluster, service, td_a, timeout_s=_left(_SETTLE_TIMEOUT_S))
        lines_a = _log_lines(ctx, log_group, task_a, f"TOKEN={token_a}",
                             timeout_s=_left(_LOG_TIMEOUT_S))
        assert any(m == f"TOKEN={token_a}" for m in lines_a), (
            f"the initial task's own stream must print token A; got {lines_a[-5:]!r}")

        # ---------------- phase 2: roll forward by replacing the task definition ----------------
        # Every AWS::ECS::TaskDefinition property is replace-on-update.
        cfn.update_stack(StackName=stack, UsePreviousTemplate=True,
                         Parameters=params(token_b, _GOOD_SCRIPT), Capabilities=["CAPABILITY_IAM"])
        updated = _wait_stack(cfn, stack, {"UPDATE_COMPLETE"}, timeout_s=_left(_UPDATE_TIMEOUT_S))
        td_b = {o["OutputKey"]: o["OutputValue"] for o in updated.get("Outputs", [])}[
            "TaskDefinitionArn"]
        assert td_b != td_a, (
            f"a TaskDefinition property change must REPLACE the resource, minting a new ARN; the "
            f"stack still reports {td_b!r}")
        desc_a = ecs.describe_task_definition(taskDefinition=td_a)["taskDefinition"]
        desc_b = ecs.describe_task_definition(taskDefinition=td_b)["taskDefinition"]
        assert desc_b["family"] == desc_a["family"] == family, (
            f"both revisions must share the template's Family {family!r}; got "
            f"{desc_a['family']!r} and {desc_b['family']!r}")
        assert desc_b["revision"] == desc_a["revision"] + 1, (
            f"the replacement must be the NEXT revision of the family: old {desc_a['revision']!r}, "
            f"new {desc_b['revision']!r}")
        env_b = {e["name"]: e["value"] for e in desc_b["containerDefinitions"][0]["environment"]}
        assert env_b.get("TOKEN") == token_b, f"revision B carries TOKEN {env_b!r}"
        svc = _service(ecs, cluster, service)
        assert svc["taskDefinition"] == td_b, (
            f"after UPDATE_COMPLETE the service must run the new revision; it runs "
            f"{svc['taskDefinition']!r}, wanted {td_b!r}")
        task_b = _sole_running_task(ecs, cluster, service, td_b, timeout_s=_left(_SETTLE_TIMEOUT_S))
        assert task_b != task_a, f"the roll-forward must REPLACE the task; still {task_a!r}"
        lines_b = _log_lines(ctx, log_group, task_b, f"TOKEN={token_b}",
                             timeout_s=_left(_LOG_TIMEOUT_S))
        assert not any(token_a in m for m in lines_b), (
            f"the revision-B container must not print token A; got {lines_b[-5:]!r}")

        # ---------------- phase 3: a revision that exits 1 must be refused ----------------
        update_started_ms = int(time.time() * 1000)
        cfn.update_stack(StackName=stack, UsePreviousTemplate=True,
                         Parameters=params(token_c, _BAD_SCRIPT), Capabilities=["CAPABILITY_IAM"])
        bad_seen = {}
        final = _wait_stack(
            cfn, stack, {"UPDATE_ROLLBACK_COMPLETE"}, timeout_s=_left(_ROLLBACK_TIMEOUT_S),
            on_poll=lambda: _sample_bad_tasks(ecs, cluster, service, td_b, bad_seen))
        rolled_back_ms = int(time.time() * 1000)
        final_out = {o["OutputKey"]: o["OutputValue"] for o in final.get("Outputs", [])}
        assert final_out["TaskDefinitionArn"] == td_b, (
            f"UPDATE_ROLLBACK_COMPLETE must restore the stack's TaskDefinition to the last good "
            f"ARN {td_b!r}; it reports {final_out['TaskDefinitionArn']!r}")

        td_c = _failed_update_taskdef(cfn, stack, update_started_ms)
        assert td_c != td_b, f"the failing update must have minted its own revision; got {td_c!r}"
        desc_c = ecs.describe_task_definition(taskDefinition=td_c)["taskDefinition"]
        assert desc_c["family"] == family and desc_c["revision"] == desc_b["revision"] + 1, (
            f"the failing revision must be {family}:{desc_b['revision'] + 1}; got "
            f"{desc_c['family']}:{desc_c['revision']}")
        service_failure = _service_update_failure(cfn, stack, update_started_ms)
        assert service_failure is not None, (
            "the stack must have rolled back BECAUSE the Service resource failed its update; no "
            "UPDATE_FAILED event for logical id Service was recorded after the update began")

        # The containers of revision C really ran and really exited 1 -- the rollback is about
        # their behaviour, not an admission-time refusal.
        _sample_bad_tasks(ecs, cluster, service, td_b, bad_seen)
        bad_for_c = {a: r for a, r in bad_seen.items() if r["td"] == td_c}
        exited_1 = [a for a, r in bad_for_c.items() if 1 in r["exit_codes"]]
        assert exited_1, (
            f"at least one revision-C task must have run its container to exit code 1; observed "
            f"{bad_for_c!r}")

        # ECS's own record of the deployment: ROLLBACK_SUCCESSFUL, breaker TRIGGERED, rolled back
        # onto the revision-B service revision.
        dep = _poll_until(
            lambda: _deployment_targeting(ecs, cluster, service, td_c),
            lambda d: d is not None and d.get("status") == "ROLLBACK_SUCCESSFUL",
            timeout_s=_left(_DEPLOYMENT_RECORD_TIMEOUT_S), interval_s=10,
            description="the service deployment targeting revision C reaches ROLLBACK_SUCCESSFUL")
        breaker = dep.get("deploymentCircuitBreaker") or {}
        assert breaker.get("status") == "TRIGGERED", (
            f"the rollback must have been driven by the circuit breaker; deploymentCircuitBreaker "
            f"is {breaker!r}")
        assert breaker.get("failureCount", 0) >= 1, f"breaker counted no failures: {breaker!r}"
        rollback_rev = (dep.get("rollback") or {}).get("serviceRevisionArn")
        assert rollback_rev, f"a ROLLBACK_SUCCESSFUL deployment must name its target: {dep!r}"
        rev = ecs.describe_service_revisions(serviceRevisionArns=[rollback_rev])[
            "serviceRevisions"][0]
        assert rev["taskDefinition"] == td_b, (
            f"the circuit breaker must roll back onto the last-known-good revision {td_b!r}; its "
            f"rollback revision runs {rev['taskDefinition']!r}")

        svc = _service(ecs, cluster, service)
        assert svc["taskDefinition"] == td_b, (
            f"after the rollback the service's taskDefinition must be the last-known-good ARN "
            f"{td_b!r}; got {svc['taskDefinition']!r}")
        assert svc["desiredCount"] == 1, f"desiredCount moved: {svc['desiredCount']!r}"
        survivor = _sole_running_task(ecs, cluster, service, td_b,
                                      timeout_s=_left(_SETTLE_TIMEOUT_S))
        fresh = _log_events_after(ctx, log_group, survivor, f"TOKEN={token_b}", rolled_back_ms,
                                  timeout_s=_left(_LOG_TIMEOUT_S))
        assert fresh, (
            f"the good token must still be SERVED after the rollback: no 'TOKEN={token_b}' event "
            f"newer than the rollback in the surviving task's stream")
        assert not any(token_c in m for m in fresh), (
            f"the surviving container must not be printing token C; got {fresh[-5:]!r}")

        # ---------------- phase 4: teardown, asserted ----------------
        cfn.delete_stack(StackName=stack)
        _wait_stack(cfn, stack, {"DELETE_COMPLETE"},
                    timeout_s=max(60.0, deadline - time.monotonic()))
        state["deleted"] = True
        clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
        assert all(c.get("status") == "INACTIVE" for c in clusters), (
            f"DELETE_COMPLETE must take the cluster with it; describe_clusters says {clusters!r}")
    finally:
        # Teardown inline under this check's own budget: a Fargate stack's delete (service drain,
        # then the subnet waiting on ENI release) is slow. A no-op when phase 4 already ran.
        _teardown()


_PREFIX = "sim2real-xsvc-cfnecsrb-"

# One overall budget; each stage's cap is also clipped to what is left, with the delete's share
# reserved.
_TOTAL_BUDGET_S = 1740
_CREATE_TIMEOUT_S = 600         # VPC + IGW + role + cluster + first Fargate task to steady state
_UPDATE_TIMEOUT_S = 600         # new revision placed, pulled, started; old task drained
_ROLLBACK_TIMEOUT_S = 900       # >=3 failed attempts, breaker trips, ECS + CFN roll back
_SETTLE_TIMEOUT_S = 180         # the old task leaving the RUNNING set after the stack settles
_LOG_TIMEOUT_S = 180            # awslogs stream creation, then event delivery
_DEPLOYMENT_RECORD_TIMEOUT_S = 180
_DELETE_TIMEOUT_S = 480         # service drain, subnet waits for Fargate ENI release, VPC

_CONTAINER = "app"
_STREAM_PREFIX = "tok"

# busybox pinned BY DIGEST, so the container's behaviour is a property of one image, not of
# whatever `latest` is today.
_BUSYBOX = ("public.ecr.aws/docker/library/busybox"
            "@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")

# The good command prints its token every 5 s, so "still being served" is testable as an event
# newer than a given instant. The bad one prints once and exits 1.
_GOOD_SCRIPT = 'trap "exit 0" TERM; while true; do echo "TOKEN=$TOKEN"; sleep 5; done'
_BAD_SCRIPT = 'echo "TOKEN=$TOKEN"; exit 1'

_TAGS = [{"Key": "sim2real", "Value": "deploy-ecs-2-cfn-rollback"}]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {k: {"Type": "String"} for k in (
        "ClusterName", "ServiceName", "Family", "LogGroupName", "Zone", "Token", "Script")},
    "Resources": {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
            "CidrBlock": "10.197.0.0/24", "EnableDnsSupport": True, "EnableDnsHostnames": True,
            "Tags": _TAGS}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": _TAGS}},
        "IgwAttach": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.197.0.0/25",
            "AvailabilityZone": {"Ref": "Zone"}, "MapPublicIpOnLaunch": True, "Tags": _TAGS}},
        "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "Tags": _TAGS}},
        "DefaultRoute": {"Type": "AWS::EC2::Route", "DependsOn": "IgwAttach", "Properties": {
            "RouteTableId": {"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": {"Ref": "Igw"}}},
        "SubnetRoutes": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
            "SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}}},
        "TaskSg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "sim2real deploy-ecs-2 egress only", "VpcId": {"Ref": "Vpc"},
            "Tags": _TAGS}},
        "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "LogGroupName": {"Ref": "LogGroupName"}, "RetentionInDays": 1}},
        "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole"}]},
            "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                              "service-role/AmazonECSTaskExecutionRolePolicy"}],
            "Tags": _TAGS}},
        "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {
            "ClusterName": {"Ref": "ClusterName"}, "Tags": _TAGS}},
        "TaskDef": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
            "Family": {"Ref": "Family"}, "NetworkMode": "awsvpc",
            "RequiresCompatibilities": ["FARGATE"], "Cpu": "256", "Memory": "512",
            "ExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
            "ContainerDefinitions": [{
                "Name": _CONTAINER, "Image": _BUSYBOX, "Essential": True,
                "Command": ["sh", "-c", {"Ref": "Script"}],
                "Environment": [{"Name": "TOKEN", "Value": {"Ref": "Token"}}],
                "StopTimeout": 2,
                "LogConfiguration": {"LogDriver": "awslogs", "Options": {
                    "awslogs-group": {"Ref": "Logs"},
                    "awslogs-region": {"Ref": "AWS::Region"},
                    "awslogs-stream-prefix": _STREAM_PREFIX}}}],
            "Tags": _TAGS}},
        "Service": {"Type": "AWS::ECS::Service", "DependsOn": ["DefaultRoute", "SubnetRoutes"],
                    "Properties": {
            "Cluster": {"Ref": "Cluster"}, "ServiceName": {"Ref": "ServiceName"},
            "TaskDefinition": {"Ref": "TaskDef"}, "DesiredCount": 1, "LaunchType": "FARGATE",
            "DeploymentConfiguration": {
                "MinimumHealthyPercent": 100, "MaximumPercent": 200,
                "DeploymentCircuitBreaker": {"Enable": True, "Rollback": True}},
            "NetworkConfiguration": {"AwsvpcConfiguration": {
                "Subnets": [{"Ref": "Subnet"}], "SecurityGroups": [{"Ref": "TaskSg"}],
                "AssignPublicIp": "ENABLED"}},
            "Tags": _TAGS}},
    },
    "Outputs": {
        "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
        "TaskDefinitionArn": {"Value": {"Ref": "TaskDef"}},
        "ServiceArn": {"Value": {"Ref": "Service"}},
    },
}


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result). Raises on a deadline miss."""
    end = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < end:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last: {last!r}")


def _ensure_ecs_slr(ctx):
    """Ensure AWSServiceRoleForECS exists; CreateService makes it implicitly but not in time on an
    account that never used ECS. Account-level and shared, so no teardown."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        # The role already exists.
        taken = ("Service role name AWSServiceRoleForECS has been taken in this account, "
                 "please try a different suffix.")
        if (exc.response.get("Error", {}).get("Code") != "InvalidInput"
                or exc.response.get("Error", {}).get("Message") != taken):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc

    def _ecs_slr_arn():
        try:
            return iam.get_role(RoleName="AWSServiceRoleForECS")["Role"]["Arn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return None
            raise

    _poll_until(_ecs_slr_arn, lambda arn: arn is not None, timeout_s=120.0, interval_s=5.0,
                description="IAM serving the ECS service-linked role")


def _usable_zone(ctx):
    """An AZ derived from the account, never named: AZ names are per-account aliases."""
    zones = sorted(z["ZoneName"] for z in ctx.client("ec2").describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"no available availability zone in {ctx.region}"
    return zones[0]


_TERMINAL = ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED", "DELETE_FAILED",
           "UPDATE_ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
           "CREATE_COMPLETE", "DELETE_COMPLETE", "UPDATE_FAILED")


def _wait_stack(cfn, stack, want, *, timeout_s, on_poll=None):
    """Poll DescribeStacks until a TERMINAL status. Returns the stack if it is one of `want`,
    else fails quoting the status and the first failure reasons -- a stack that settles somewhere
    else (UPDATE_COMPLETE for a revision that cannot run, ROLLBACK_FAILED) is the defect."""
    end = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < end:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        except ClientError as exc:
            if "DELETE_COMPLETE" in want and "does not exist" in str(exc):
                return {"StackStatus": "DELETE_COMPLETE"}
            raise
        status = last["StackStatus"]
        if status in want:
            return last
        if status in _TERMINAL and not status.endswith("_IN_PROGRESS"):
            raise AssertionError(f"stack {stack} settled at {status!r}, wanted {sorted(want)!r}; "
                                 f"reasons: {_failure_reasons(cfn, stack)!r}")
        if on_poll is not None:
            _safe(on_poll)
        time.sleep(2)
    raise AssertionError(f"stack {stack} never reached {sorted(want)!r} within {timeout_s:.0f}s; "
                         f"last status {(last or {}).get('StackStatus')!r}")


def _stack_events(cfn, stack):
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        out.extend(page.get("StackEvents", []))
    return out


def _failure_reasons(cfn, stack):
    evs = _safe(lambda: _stack_events(cfn, stack)) or []
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
            for e in evs if e["ResourceStatus"].endswith("FAILED")][:6]


def _after(event, since_ms):
    return event["Timestamp"].timestamp() * 1000 >= since_ms - 2000


def _failed_update_taskdef(cfn, stack, since_ms):
    """The physical id CloudFormation minted for TaskDef during the update that failed: the
    EARLIEST TaskDef UPDATE_COMPLETE after the update began (the rollback emits a later one)."""
    evs = sorted((e for e in _stack_events(cfn, stack)
                  if e["LogicalResourceId"] == "TaskDef" and e["ResourceStatus"] == "UPDATE_COMPLETE"
                  and _after(e, since_ms)), key=lambda e: e["Timestamp"])
    assert evs, "the failing update recorded no TaskDef UPDATE_COMPLETE (no replacement minted)"
    return evs[0].get("PhysicalResourceId")


def _service_update_failure(cfn, stack, since_ms):
    for e in _stack_events(cfn, stack):
        if (e["LogicalResourceId"] == "Service" and e["ResourceStatus"] == "UPDATE_FAILED"
                and _after(e, since_ms)):
            print(f"  Service UPDATE_FAILED reason: {e.get('ResourceStatusReason')!r}")
            return e
    return None


def _service(ecs, cluster, service):
    return ecs.describe_services(cluster=cluster, services=[service])["services"][0]


def _task_arns(ecs, cluster, service, desired):
    out = []
    for page in ecs.get_paginator("list_tasks").paginate(
            cluster=cluster, serviceName=service, desiredStatus=desired):
        out.extend(page.get("taskArns", []))
    return out


def _sole_running_task(ecs, cluster, service, td, *, timeout_s):
    """The ONE RUNNING task of the service, which must belong to revision `td`."""
    def _probe():
        arns = _task_arns(ecs, cluster, service, "RUNNING")
        if not arns:
            return []
        return [(t["taskArn"], t["taskDefinitionArn"], t["lastStatus"])
                for t in ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]]
    got = _poll_until(_probe, lambda ts: len(ts) == 1 and ts[0][1] == td and ts[0][2] == "RUNNING",
                      timeout_s=timeout_s, interval_s=5,
                      description=f"exactly one RUNNING task, of revision {td}")
    return got[0][0]


def _sample_bad_tasks(ecs, cluster, service, good_td, seen):
    """Accumulate every non-good task's observed states and container exit codes. Stopped tasks
    are sampled while they are listable rather than reconstructed afterwards."""
    arns = _task_arns(ecs, cluster, service, "RUNNING") + _task_arns(ecs, cluster, service,
                                                                     "STOPPED")
    for i in range(0, len(arns), 100):
        for t in ecs.describe_tasks(cluster=cluster, tasks=arns[i:i + 100])["tasks"]:
            if t["taskDefinitionArn"] == good_td:
                continue
            rec = seen.setdefault(t["taskArn"], {"td": t["taskDefinitionArn"], "statuses": set(),
                                                 "exit_codes": set(), "reasons": set()})
            rec["statuses"].add(t.get("lastStatus"))
            for c in t.get("containers", []):
                if c.get("exitCode") is not None:
                    rec["exit_codes"].add(c["exitCode"])
            if t.get("stoppedReason"):
                rec["reasons"].add(t["stoppedReason"])


def _deployment_targeting(ecs, cluster, service, td):
    arns = []
    token = None
    while True:
        kw = {"cluster": cluster, "service": service}
        if token:
            kw["nextToken"] = token
        resp = ecs.list_service_deployments(**kw)
        arns.extend(d["serviceDeploymentArn"] for d in resp.get("serviceDeployments", []))
        token = resp.get("nextToken")
        if not token:
            break
    for i in range(0, len(arns), 20):
        for d in ecs.describe_service_deployments(
                serviceDeploymentArns=arns[i:i + 20])["serviceDeployments"]:
            target = (d.get("targetServiceRevision") or {}).get("arn")
            if not target:
                continue
            rev = ecs.describe_service_revisions(serviceRevisionArns=[target])[
                "serviceRevisions"][0]
            if rev.get("taskDefinition") == td:
                return d
    return None


def _stream(task_arn):
    return f"{_STREAM_PREFIX}/{_CONTAINER}/{task_arn.rsplit('/', 1)[-1]}"


def _events(ctx, group, task_arn):
    logs = ctx.client("logs")
    out, token, seen = [], None, set()
    while True:
        kw = dict(logGroupName=group, logStreamName=_stream(task_arn), startFromHead=True)
        if token:
            kw["nextToken"] = token
        resp = _safe(lambda k=dict(kw): logs.get_log_events(**k))
        if resp is None:
            return out
        out.extend(resp.get("events", []))
        token = resp.get("nextForwardToken")
        if not token or token in seen:
            return out
        seen.add(token)


def _log_lines(ctx, group, task_arn, sentinel, *, timeout_s):
    evs = _poll_until(lambda: _events(ctx, group, task_arn),
                      lambda es: any(e.get("message") == sentinel for e in es),
                      timeout_s=timeout_s, interval_s=5,
                      description=f"{sentinel!r} delivered to {group}/{_stream(task_arn)}")
    return [e.get("message", "") for e in evs]


def _log_events_after(ctx, group, task_arn, sentinel, since_ms, *, timeout_s):
    """Messages written at or after `since_ms`, waited on until one of them is `sentinel`."""
    evs = _poll_until(
        lambda: [e for e in _events(ctx, group, task_arn) if e.get("timestamp", 0) >= since_ms],
        lambda es: any(e.get("message") == sentinel for e in es),
        timeout_s=timeout_s, interval_s=5,
        description=f"a fresh {sentinel!r} in {group}/{_stream(task_arn)}")
    return [e.get("message", "") for e in evs]


def _task_definition_teardown(ctx, stack_name: str):
    """Delete every task definition revision the stack registers once it is deleted (CFN only
    deregisters them). Returns the stack-id recorder; register it after the stack's deletion."""
    state: dict = {}
    ctx.on_cleanup(lambda: _delete_stack_task_definitions(ctx, state.get("stack_id")))

    def _record_stack_id() -> None:
        try:
            state["stack_id"] = ctx.client("cloudformation").describe_stacks(
                StackName=stack_name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise

    return _record_stack_id


def _delete_stack_task_definitions(ctx, stack_id) -> None:
    """Wait for the stack's deletion, then delete each task definition revision it registered."""
    if stack_id is None:
        return
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    arns, pending, seen = set(), [stack_id], set()
    while pending:
        sid = pending.pop()
        if sid in seen:
            continue
        seen.add(sid)
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=sid):
            for event in page["StackEvents"]:
                physical = event.get("PhysicalResourceId") or ""
                if not physical.startswith("arn:") or event["ResourceStatus"] not in (
                        "CREATE_COMPLETE", "UPDATE_COMPLETE"):
                    continue
                if event["ResourceType"] == "AWS::ECS::TaskDefinition":
                    arns.add(physical)
                elif event["ResourceType"] == "AWS::CloudFormation::Stack" and physical != sid:
                    pending.append(physical)
    for arn in sorted(arns):
        try:
            status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        except ClientError as exc:
            if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
                continue
            raise
        if status == "DELETE_IN_PROGRESS":
            continue
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
