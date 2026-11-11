"""xsvc-autoscaling-3-launch-hook-lambda-error-times-out-to-abandon."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-autoscaling-3-launch-hook-lambda-error-times-out-to-abandon"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "events", "lambda"]

_LIFECYCLE = "EC2 Instance-launch Lifecycle Action"
_SUCCESS = "EC2 Instance Launch Successful"
_UNSUCCESS = "EC2 Instance Launch Unsuccessful"
_HEARTBEAT_TIMEOUT_S = 30  # the API minimum — keeps the auto-ABANDON wait short


# timing:real-time — workflow: 30 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks-overview.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:eventing", "concern:e2e",
      "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A launch hook (DefaultResult=ABANDON) whose EventBridge-routed Lambda always raises times
    out: the instance is terminated before InService and only Launch Unsuccessful is emitted.
    A control completing the same hook directly proves the group can still admit an instance.
    """
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-lcf-")
    hook = "sim2real-launch-hook"
    metadata = json.dumps({"check": CHECK, "group": name})

    subnet = _network(ctx, ec2, name)
    lt = _launch_template(ctx, ec2, name)
    _create_group(ctx, asg, name, lt, subnet, hook, metadata, _HEARTBEAT_TIMEOUT_S)

    fn_arn = _handler(ctx, lam, logs, account, name)
    _route(ctx, events, lam, name, fn_arn, [_LIFECYCLE, _SUCCESS, _UNSUCCESS])

    # --- negative leg: the Lambda always raises, so the hook can only resolve by timing out.
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    bad_id = _poll(lambda: [i["InstanceId"] for i in _group(asg, name)["Instances"]],
                   lambda ids: len(ids) == 1, timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                   what=f"group {name} launching its first instance", ctx=ctx)[0]

    recs = _poll(lambda: _records(logs, name),
                  lambda rs: any(r["event"]["detail-type"] == _LIFECYCLE and
                                 r["event"]["detail"].get("EC2InstanceId") == bad_id for r in rs),
                  ctx=ctx, timeout_s=_budget_s(ctx, 180.0), interval_s=1.0,
                  what=f"the Lambda receiving the launch hook event for {bad_id}")
    lifecycle = [r for r in recs if r["event"]["detail-type"] == _LIFECYCLE
                 and r["event"]["detail"].get("EC2InstanceId") == bad_id]
    assert len(lifecycle) == 1, f"exactly one lifecycle event was expected for {bad_id}: {lifecycle!r}"
    lc = lifecycle[0]
    d = lc["event"]["detail"]
    assert (d.get("Origin"), d.get("Destination")) == ("EC2", "AutoScalingGroup"), (
        f"a plain scale-out launch is Origin=EC2 Destination=AutoScalingGroup: {d!r}"
    )
    assert lc.get("outcome") == "raised", (
        f"the handler must have raised rather than completed the hook: {lc.get('outcome')!r}"
    )

    seen_states: set[str] = set()

    def _watch_bad():
        g = _group(asg, name)
        ids = [i["InstanceId"] for i in g["Instances"]] if g else []
        for i in (g or {}).get("Instances", []):
            if i["InstanceId"] == bad_id:
                seen_states.add(i["LifecycleState"])
        return ids

    _poll(_watch_bad, lambda ids: bad_id not in ids, ctx=ctx, timeout_s=_budget_s(ctx, 600.0),
          interval_s=1.0,
          what=f"instance {bad_id} leaving the group after its hook timed out to ABANDON")
    assert "InService" not in seen_states, (
        f"the abandoned instance reached InService at some point: states seen were "
        f"{sorted(seen_states)!r}"
    )
    ec2_state = _poll(lambda: _instance_state(ec2, bad_id),
                       lambda s: s in ("shutting-down", "terminated", "__gone__"),
                       ctx=ctx, timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                       what=f"instance {bad_id} actually terminating")
    assert ec2_state in ("shutting-down", "terminated", "__gone__"), (
        f"the abandoned instance was not terminated: {ec2_state!r}"
    )

    recs = _poll(lambda: _records(logs, name),
                  lambda rs: any(r["event"]["detail-type"] == _UNSUCCESS and
                                 r["event"]["detail"].get("EC2InstanceId") == bad_id for r in rs),
                  ctx=ctx, timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                  what=f"'{_UNSUCCESS}' arriving for the timed-out instance {bad_id}")
    unsuccess = [r for r in recs if r["event"]["detail-type"] == _UNSUCCESS
                 and r["event"]["detail"].get("EC2InstanceId") == bad_id]
    success = [r for r in recs if r["event"]["detail-type"] == _SUCCESS
               and r["event"]["detail"].get("EC2InstanceId") == bad_id]
    assert len(unsuccess) == 1, f"exactly one '{_UNSUCCESS}' event was expected: {unsuccess!r}"
    ud = unsuccess[0]["event"]["detail"]
    # A hook timing out to its DefaultResult reports StatusCode=Cancelled
    # (not "Unsuccessful") with the abandonment named in StatusMessage — a timed-out launch and an
    # explicitly-ABANDONed one share this detail-type but are told apart by that message.
    assert ud.get("StatusCode") == "Cancelled", f"StatusCode: {ud!r}"
    assert "abandoned" in ud.get("StatusMessage", "").lower(), (
        f"the cancellation must name the heartbeat-timeout abandonment: {ud!r}"
    )
    assert (ud.get("Origin"), ud.get("Destination")) == ("EC2", "AutoScalingGroup"), (
        f"'{_UNSUCCESS}' must carry Origin=EC2 Destination=AutoScalingGroup: {ud!r}"
    )
    assert success == [], (
        f"an instance abandoned by hook timeout must never report Launch Successful: "
        f"{[r['event'] for r in success]!r}"
    )

    # --- positive control: same group, same hook, completed directly — the group still admits.
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=0)
    _poll(lambda: len(_group(asg, name)["Instances"]), lambda n: n == 0,
          ctx=ctx, timeout_s=_budget_s(ctx, 300.0),
          interval_s=1.0, what=f"group {name} draining back to zero instances")
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    good_id = _poll(lambda: [i["InstanceId"] for i in _group(asg, name)["Instances"]
                              if i["InstanceId"] != bad_id],
                     lambda ids: len(ids) == 1, timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                     what=f"group {name} launching the control instance", ctx=ctx)[0]
    hooks = asg.describe_lifecycle_hooks(AutoScalingGroupName=name)["LifecycleHooks"]
    pending = _poll(lambda: _asg_instance_state(asg, good_id), lambda s: s == "Pending:Wait",
                     ctx=ctx, timeout_s=_budget_s(ctx, 120.0), interval_s=1.0,
                     what=f"control instance {good_id} parked at Pending:Wait")
    assert pending == "Pending:Wait", f"control instance state: {pending!r}"
    # InstanceId identifies the pending action in place of a token — CompleteLifecycleAction
    # accepts either, and the control leg deliberately bypasses the Lambda that holds the token.
    asg.complete_lifecycle_action(
        AutoScalingGroupName=name, LifecycleHookName=hook,
        LifecycleActionResult="CONTINUE", InstanceId=good_id,
    )
    good_state = _poll(lambda: _asg_instance_state(asg, good_id), lambda s: s == "InService",
                        ctx=ctx, timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                        what=f"control instance {good_id} reaching InService once completed")
    assert good_state == "InService", (
        f"a hook completed directly must still admit the instance: {good_state!r}; "
        f"hooks on the group were {hooks!r}"
    )


# ===== helpers =====

_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.92.0.0/16"
_SUBNET_CIDR = "10.92.1.0/24"
_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound",
         "InvalidLaunchTemplateId.NotFound")

_HANDLER = textwrap.dedent('''
    import json, time
    import boto3

    MARK = "__MARK__"
    LIFECYCLE = "EC2 Instance-launch Lifecycle Action"

    def lambda_handler(event, context):
        rec = {"mark": MARK, "received_at": time.time(), "event": event}
        if event.get("detail-type") == LIFECYCLE:
            rec["outcome"] = "raised"
            print(json.dumps(rec))
            raise RuntimeError("sim2real: deliberately failing lifecycle handler")
        print(json.dumps(rec))
        return {"ok": True}
''')


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, what, ctx=None):
    """Bounded poll that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _retry_dependency(fn, timeout_s=30.0):
    """Retry a delete on DependencyViolation every 2 s to a deadline inside the shared cleanup
    budget, then raise; an already-deleted resource is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE:
                return
            if _code(exc) != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _network(ctx, ec2, name):
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {_INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=usable[0],
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))
    return subnet


def _launch_template(ctx, ec2, name):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": _INSTANCE_TYPE,
            "TagSpecifications": [
                {"ResourceType": "instance",
                 "Tags": _tags_for(name) + [{"Key": "sim2real-asg", "Value": name}]},
                {"ResourceType": "volume", "Tags": _tags_for(name)}]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_for(name)}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_launch_template(LaunchTemplateId=lt)))
    ctx.on_cleanup(lambda: _terminate_group_instances(ec2, name))
    return lt


def _create_group(ctx, asg, name, lt, subnet, hook, metadata, heartbeat_s):
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=1, DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        LifecycleHookSpecificationList=[{
            "LifecycleHookName": hook,
            "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
            "HeartbeatTimeout": heartbeat_s, "DefaultResult": "ABANDON",
            "NotificationMetadata": metadata}],
        Tags=[{"Key": "sim2real", "Value": "1", "PropagateAtLaunch": True}])
    ctx.on_cleanup(lambda: _delete_group(asg, name))
    hooks = asg.describe_lifecycle_hooks(AutoScalingGroupName=name)["LifecycleHooks"]
    assert [(h["LifecycleHookName"], h["DefaultResult"], h["HeartbeatTimeout"]) for h in hooks] \
        == [(hook, "ABANDON", heartbeat_s)], f"the group must carry exactly the launch hook: {hooks!r}"


def _group(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0] if groups else None


def _asg_instance_state(asg, iid):
    got = asg.describe_auto_scaling_instances(InstanceIds=[iid])["AutoScalingInstances"]
    return got[0]["LifecycleState"] if got else None


def _delete_group(asg, name):
    """Fire ForceDelete and return without polling for the group to disappear.

    AWS tears the group down asynchronously; polling would spend the shared cleanup budget.
    """
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in str(exc).lower():
            raise


def _instance_state(ec2, iid):
    try:
        resv = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_group_instances(ec2, name):
    """Terminate the group's instances without waiting: a safety net behind ForceDelete."""
    ids = [i["InstanceId"] for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "tag:sim2real-asg", "Values": [name]},
                 {"Name": "instance-state-name",
                  "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}])
        for r in page["Reservations"] for i in r["Instances"]]
    if ids:
        ec2.terminate_instances(InstanceIds=ids)


def _delete_role(iam, role):
    try:
        for p in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=p)
        iam.delete_role(RoleName=role)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise


def _reap_log_group(logs, group):
    """Delete the function's log group once, without waiting.

    A buffered stream can flush after delete_function and recreate the group.
    """
    try:
        logs.delete_log_group(logGroupName=group)
    except ClientError as exc:
        if _code(exc) != "ResourceNotFoundException":
            raise


def _handler(ctx, lam, logs, account, name):
    """The lifecycle handler: role scoped to this group's hook, then the always-failing function."""
    iam = ctx.client("iam")
    role = name[:64]
    iam.create_role(
        RoleName=role, Path="/sim2real/", Tags=[{"Key": "sim2real", "Value": "1"}],
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}))
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(RoleName=role, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                           "logs:PutLogEvents"],
             "Resource": f"arn:aws:logs:{ctx.region}:{account}:log-group:/aws/lambda/{name}*"}]}))
    role_arn = iam.get_role(RoleName=role)["Role"]["Arn"]

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER.replace("__MARK__", name))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=20, MemorySize=128, Tags={"sim2real": "1"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            if _code(exc) == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll(lambda: lam.get_function_configuration(FunctionName=name)["State"],
          lambda s: s == "Active", timeout_s=120.0, interval_s=2.0, what=f"Lambda {name} Active")
    lam.put_function_event_invoke_config(FunctionName=name, MaximumRetryAttempts=0)
    return arn


def _route(ctx, events, lam, name, fn_arn, detail_types):
    rule = name[:64]
    rule_arn = events.put_rule(
        Name=rule, State="ENABLED", Description="sim2real lifecycle-hook check",
        EventPattern=json.dumps({"source": ["aws.autoscaling"], "detail-type": detail_types,
                                 "detail": {"AutoScalingGroupName": [name]}}),
        Tags=[{"Key": "sim2real", "Value": "1"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    lam.add_permission(FunctionName=name, StatementId="events-invoke",
                       Action="lambda:InvokeFunction", Principal="events.amazonaws.com",
                       SourceArn=rule_arn)
    resp = events.put_targets(Rule=rule, Targets=[{"Id": "fn", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["fn"], Force=True))
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed for {rule}: {resp!r}"


def _records(logs, name):
    """Every observation the handler printed, oldest first; [] before the group exists."""
    out = []
    kwargs = {"logGroupName": f"/aws/lambda/{name}", "filterPattern": f'"{name}"'}
    try:
        while True:
            page = logs.filter_log_events(**kwargs)
            for e in page.get("events", []):
                msg = e["message"].strip()
                if msg.startswith("{"):
                    rec = json.loads(msg)
                    if rec.get("mark") == name:
                        out.append(rec)
            if not page.get("nextToken"):
                break
            kwargs["nextToken"] = page["nextToken"]
    except ClientError as exc:
        if _code(exc) != "ResourceNotFoundException":
            raise
    return sorted(out, key=lambda r: r["received_at"])


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the ENIs to
# go, retry DependencyViolation inside the same window, and raise a final failure naming the ENIs
# still attached. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
