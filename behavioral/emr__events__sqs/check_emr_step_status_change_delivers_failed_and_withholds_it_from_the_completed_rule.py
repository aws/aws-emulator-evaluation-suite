"""emr-step-status-change-delivers-failed-and-withholds-it-from-the-completed-rule."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-step-status-change-delivers-failed-and-withholds-it-from-the-completed-rule"
GROUP = "eventing"
SERVICES = ["emr", "events", "sqs"]

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-step-status-change-events"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
DETAIL_TYPE = "EMR Step Status Change"
#: Fixed absence window, held after both rules delivered their own step's event.
ABSENCE_HOLD_SECONDS = 10
_POLL_S = 2.0


def _swallow(fn):
    """Run fn(), swallowing any exception. TEARDOWN ONLY — never on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, description, ctx):
    """Poll probe() until predicate(result); RAISE on timeout (never return the last value)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts=60, delay=2):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emrev-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emrev-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM eventual consistency; RunJobFlow's transient retry is the real backstop.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=ec2_role)
            break
        except Exception:  # noqa: BLE001 — prerequisite polling only, never an assertion
            time.sleep(2)
    return svc_role, ec2_role


def _retry_ec2_delete(fn, budget_s=300):
    """Run an EC2 teardown call, retrying while its target is still held by something winding down."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code not in ("DependencyViolation", "InvalidNetworkInterface.InUse") or time.monotonic() > deadline:
                raise
            time.sleep(_POLL_S)


def _delete_vpc(ec2, vpc_id):
    """Delete the VPC after its non-default security groups: EMR creates its managed primary/core
    groups in it, and they reference each other, so their rules are revoked before the deletes."""
    groups = [g for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"] if g["GroupName"] != "default"]
    for g in groups:
        if g.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        if g.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        _retry_ec2_delete(lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid))
    _retry_ec2_delete(lambda: ec2.delete_vpc(VpcId=vpc_id))


def _pick_subnet(ctx):
    """A private subnet in a new VPC, in an available AZ that offers INSTANCE_TYPE; the VPC has no
    internet route, and an S3 gateway endpoint is its only way out.

    Offerings say nothing about zone state, so both lookups are needed. Cleanups run LIFO.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted({z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]} & offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {INSTANCE_TYPE}; offerings were {sorted(offered)!r}"
    )

    vpc = ec2.create_vpc(CidrBlock="10.98.0.0/16",
                         TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.98.1.0/24", AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))

    table = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]}, {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc, VpcEndpointType="Gateway", RouteTableIds=[table],
        ServiceName=f"com.amazonaws.{ctx.region}.s3",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _TAGS}],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(ec2, endpoint))
    return subnet


def _delete_vpc_endpoint(ec2, endpoint_id):
    """DeleteVpcEndpoints reports a failed delete in Unsuccessful, not as an error: return once the
    endpoint is gone, raise on anything else."""
    bad = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]).get("Unsuccessful", [])
           if u["Error"]["Code"] != "InvalidVpcEndpointId.NotFound"]
    if bad:
        raise RuntimeError(f"delete_vpc_endpoints({endpoint_id}) failed: {bad!r}")


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id):
    """Terminate and WAIT: cleanups run LIFO with the IAM deletions registered first, so a bare
    terminate lets delete_role run while EMR still needs it — stranding the EC2 fleet."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    last = None
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(_POLL_S)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        last = state
        time.sleep(_POLL_S)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors."""
    last = None
    resp = None
    deadline = time.monotonic() + _budget_s(ctx, 300)
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("RunJobFlow succeeding: the run budget ended first; not graded")
                raise
            last = exc
            time.sleep(_POLL_S)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id))
    return cluster_id


def _make_queue(ctx, sqs, label):
    """A queue whose ReceiveMessageWaitTimeSeconds is 0, so an EMPTY receive is fast and an absence
    assertion is a real poll rather than a 20s block per attempt."""
    name = ctx.unique_name(f"sim2real-behav-emrev-{label}-")
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"ReceiveMessageWaitTimeSeconds": "0", "VisibilityTimeout": "5"},
        tags={t["Key"]: t["Value"] for t in _TAGS},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_events_to_send(sqs, queue_url, queue_arn, rule_arn):
    """Grant events.amazonaws.com sqs:SendMessage, scoped to the ONE rule that may use this queue."""
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowThisRule",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }],
        })},
    )


def _make_rule(ctx, events, label, pattern, queue_arn):
    """A rule on the default bus with one SQS target; returns (name, arn)."""
    name = ctx.unique_name(f"sim2real-behav-emrev-{label}-")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Description=f"sim2real {_SCENARIO} {label}",
        Tags=_TAGS,
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    events.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=name, Ids=["q"]))
    return name, arn


def _drain(sqs, queue_url, *, timeout_s, interval_s):
    """Read and delete every envelope in the queue, so ApproximateNumberOfMessages is usable after."""
    collected = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=0)
        # SQS omits Messages entirely on an empty receive.
        messages = resp.get("Messages", [])
        if not messages:
            break
        for m in messages:
            collected.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        time.sleep(interval_s)
    return collected


def _step(name, exit_code):
    """A step that does nothing but exit with exit_code. ActionOnFailure=CONTINUE on both, so the
    failing one does not take the cluster (or the second event) down with it."""
    return {
        "Name": name,
        "ActionOnFailure": "CONTINUE",
        "HadoopJarStep": {
            "Jar": "command-runner.jar",
            "Args": ["bash", "-c", f"exit {exit_code}"],
        },
    }


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A failing and a passing EMR step emit Step Status Change events routed by detail.state: each
    state-patterned rule's SQS queue receives exactly its step's event and never the other's.
    Payload fields (stepId, name, actionOnFailure, severity) are asserted against the docs.

    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-cloudwatch-events.html
    Reference: https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-emr.html
    """
    emr = ctx.client("emr")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    # Launched with NO steps, so the rules can be in place before any step event exists.
    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emrev-"),
        ReleaseLabel=RELEASE_LABEL,
        Applications=[{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [{
                "Name": "sim2real-primary", "InstanceRole": "MASTER",
                "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
            }],
            # True so the failing step cannot end the cluster before its event is delivered.
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        # Explicit rather than defaulted: the ordering of the two steps below is asserted.
        StepConcurrencyLevel=1,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    completed_url, completed_arn = _make_queue(ctx, sqs, "completed")
    failed_url, failed_arn = _make_queue(ctx, sqs, "failed")

    # Scoped to this cluster id so other EMR activity in the account cannot land in either queue.
    def _pattern(state):
        return {
            "source": ["aws.emr"],
            "detail-type": [DETAIL_TYPE],
            "detail": {"clusterId": [cluster_id], "state": [state]},
        }

    completed_rule, completed_rule_arn = _make_rule(
        ctx, events, "completed", _pattern("COMPLETED"), completed_arn)
    failed_rule, failed_rule_arn = _make_rule(
        ctx, events, "failed", _pattern("FAILED"), failed_arn)
    _allow_events_to_send(sqs, completed_url, completed_arn, completed_rule_arn)
    _allow_events_to_send(sqs, failed_url, failed_arn, failed_rule_arn)

    # Both rules must really be attached to their queue, or an absence below would be an artefact
    # of a missing target rather than of the pattern.
    for rule, expected in ((completed_rule, completed_arn), (failed_rule, failed_arn)):
        targets = events.list_targets_by_rule(Rule=rule)["Targets"]
        assert [t["Arn"] for t in targets] == [expected], (
            f"rule {rule!r} must have exactly the one SQS target {expected!r}, got {targets!r}"
        )

    state = _poll(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s not in ("STARTING", "BOOTSTRAPPING"),
        timeout_s=1500,
        interval_s=_POLL_S,
        ctx=ctx,
        description=f"cluster {cluster_id} provisions",
    )
    assert state == "WAITING", (
        f"the step events can only be produced by a healthy cluster; got {state!r} (reason "
        f"{emr.describe_cluster(ClusterId=cluster_id)['Cluster']['Status'].get('StateChangeReason')!r})"
    )

    pass_name = ctx.unique_name("sim2real-emrev-pass-")
    fail_name = ctx.unique_name("sim2real-emrev-fail-")
    added = emr.add_job_flow_steps(
        JobFlowId=cluster_id, Steps=[_step(pass_name, 0), _step(fail_name, 7)]
    )["StepIds"]
    assert len(added) == 2, f"AddJobFlowSteps must return two step ids, got {added!r}"
    pass_step_id, fail_step_id = added

    def _both_terminal():
        return {
            sid: emr.describe_step(ClusterId=cluster_id, StepId=sid)["Step"]["Status"]["State"]
            for sid in added
        }

    states = _poll(
        _both_terminal,
        lambda m: all(v in TERMINAL_STEP_STATES for v in m.values()),
        timeout_s=600,
        interval_s=_POLL_S,
        ctx=ctx,
        description=f"both steps on {cluster_id} reach terminal states",
    )
    assert states[pass_step_id] == "COMPLETED", (
        f"the `exit 0` step must COMPLETE so the positive control has something to deliver; got "
        f"{states[pass_step_id]!r}"
    )
    assert states[fail_step_id] == "FAILED", (
        f"the `exit 7` step must FAIL so the routed event exists at all; got "
        f"{states[fail_step_id]!r}"
    )
    both_terminal_at = time.monotonic()

    # Positive control: proves the delivery path works, so the absence below is meaningful.
    completed_msgs = _poll(
        lambda: _drain(sqs, completed_url, timeout_s=15, interval_s=1),
        lambda ms: bool(ms),
        timeout_s=300,
        interval_s=_POLL_S,
        ctx=ctx,
        description=(
            f"the COMPLETED-patterned rule delivers step {pass_step_id}'s event to its SQS queue"
        ),
    )
    latency_s = time.monotonic() - both_terminal_at

    assert len(completed_msgs) == 1, (
        f"exactly one COMPLETED event must arrive for one completing step, got "
        f"{[m.get('detail', {}).get('stepId') for m in completed_msgs]!r}"
    )
    envelope = completed_msgs[0]
    assert envelope["source"] == "aws.emr", (
        f"the envelope must come from aws.emr, got {envelope['source']!r}"
    )
    assert envelope["detail-type"] == DETAIL_TYPE, (
        f"the envelope must be a {DETAIL_TYPE!r}, got {envelope['detail-type']!r}"
    )
    detail = envelope["detail"]
    assert detail["stepId"] == pass_step_id, (
        f"the COMPLETED event must name the passing step {pass_step_id!r}, got {detail!r}"
    )
    assert detail["clusterId"] == cluster_id, (
        f"the event must name this cluster {cluster_id!r}, got {detail!r}"
    )
    assert detail["state"] == "COMPLETED", (
        f"the event delivered by the COMPLETED-patterned rule must carry state COMPLETED, got "
        f"{detail!r}"
    )
    assert detail["name"] == pass_name, (
        f"the event must carry the step's submitted name {pass_name!r}, got {detail['name']!r}"
    )
    assert detail["actionOnFailure"] == "CONTINUE", (
        f"the event must echo the step's submitted ActionOnFailure 'CONTINUE'; "
        f"got {detail.get('actionOnFailure')!r}"
    )
    assert detail["severity"] == "INFO", (
        f"a COMPLETED step event is documented INFO severity, got {detail['severity']!r}"
    )

    failed_msgs = _poll(
        lambda: _drain(sqs, failed_url, timeout_s=15, interval_s=1),
        lambda ms: bool(ms),
        timeout_s=300,
        interval_s=_POLL_S,
        ctx=ctx,
        description=(
            f"the FAILED-patterned rule delivers step {fail_step_id}'s event to its SQS queue"
        ),
    )
    assert len(failed_msgs) == 1, (
        f"exactly one FAILED event must arrive for one failing step, got "
        f"{[m.get('detail', {}).get('stepId') for m in failed_msgs]!r}"
    )
    fail_detail = failed_msgs[0]["detail"]
    assert fail_detail["stepId"] == fail_step_id, (
        f"the FAILED event must name the failing step {fail_step_id!r}, got {fail_detail!r}"
    )
    assert fail_detail["state"] == "FAILED", (
        f"the event delivered by the FAILED-patterned rule must carry state FAILED, got "
        f"{fail_detail!r}"
    )
    assert fail_detail["severity"] == "ERROR", (
        f"a FAILED step event is documented ERROR severity — the field that lets a consumer alarm "
        f"on it; got {fail_detail['severity']!r}"
    )
    assert fail_detail["message"], (
        f"the FAILED event must carry a human-readable message, got {fail_detail!r}"
    )

    # Both rules matched the same two events and each has delivered its own, so a cross-delivery
    # would land alongside them; the fixed window drains both queues about once a second.
    hold_s = ABSENCE_HOLD_SECONDS
    stray_completed = []
    stray_failed = []
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        stray_completed.extend(_drain(sqs, completed_url, timeout_s=5, interval_s=1))
        stray_failed.extend(_drain(sqs, failed_url, timeout_s=5, interval_s=1))
        time.sleep(1)

    completed_ids = [m["detail"]["stepId"] for m in stray_completed]
    failed_ids = [m["detail"]["stepId"] for m in stray_failed]
    assert not stray_completed, (
        f"the COMPLETED-patterned rule must NEVER receive the failing step's event, nor a second "
        f"copy of the passing one: over a {hold_s:.0f}s window held after both "
        f"rules delivered (delivery latency {latency_s:.0f}s on this same wiring) it received "
        f"{[(m['detail']['stepId'], m['detail']['state']) for m in stray_completed]!r}"
    )
    assert not stray_failed, (
        f"the FAILED-patterned rule must NEVER receive the passing step's event: over a "
        f"{hold_s:.0f}s window it received "
        f"{[(m['detail']['stepId'], m['detail']['state']) for m in stray_failed]!r}"
    )
    assert fail_step_id not in completed_ids and pass_step_id not in failed_ids, (
        f"cross-delivery detected: COMPLETED queue saw {completed_ids!r}, FAILED queue saw "
        f"{failed_ids!r}"
    )

    # Queue depth is a second observable besides an empty receive.
    for label, url in (("completed", completed_url), ("failed", failed_url)):
        attrs = sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        assert attrs["ApproximateNumberOfMessages"] == "0", (
            f"the {label} queue must be empty after its one expected event was consumed; "
            f"ApproximateNumberOfMessages={attrs['ApproximateNumberOfMessages']!r}"
        )
        assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
            f"the {label} queue must have nothing in flight either; "
            f"ApproximateNumberOfMessagesNotVisible="
            f"{attrs['ApproximateNumberOfMessagesNotVisible']!r}"
        )

    # PENDING/RUNNING transitions happened too; none may have been delivered.
    all_states_seen = {m["detail"]["state"] for m in completed_msgs + failed_msgs}
    assert all_states_seen == {"COMPLETED", "FAILED"}, (
        f"only the two patterned states may have been delivered across both queues — a PENDING or "
        f"RUNNING envelope would mean the state filter did nothing; saw {sorted(all_states_seen)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
