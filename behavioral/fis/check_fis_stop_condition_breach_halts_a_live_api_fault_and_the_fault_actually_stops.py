"""fis-stop-condition-breach-halts-a-live-api-fault-and-the-fault-actually-stops."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fis-stop-condition-breach-halts-a-live-api-fault-and-the-fault-actually-stops"
GROUP = "fault-injection"
SERVICES = ["fis"]

# The error an aws:fis:inject-api-internal-error action returns on AWS.
_INJECTED_ERROR_CODE = "InternalError"
_INJECTED_ERROR_MESSAGE = "An internal error has occurred"

# PT10M, deliberately long: every poll budget below ends well inside it, so an action that reads
# 'stopped' (not 'completed') was halted, never expired.
_ACTION_DURATION = "PT10M"
_ACTION_DURATION_S = 600.0
# An experiment that ends later than this cannot be attributed to the stop condition.
_MAX_ATTRIBUTABLE_RECOVERY_S = 300.0

_IAM_PROPAGATION_BUDGET_S = 120.0
_EXPERIMENT_RUNNING_TIMEOUT_S = 180.0
_ACTION_RUNNING_TIMEOUT_S = 180.0
_FAULT_VISIBLE_TIMEOUT_S = 240.0
_AUTO_STOP_TIMEOUT_S = 300.0
_RECOVERY_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """A breached CloudWatch stop condition halts a live, observed API fault: the experiment ends
    'stopped' (not 'completed') and the injected fault itself stops, well before the action's
    declared duration would have elapsed."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")
    sts = ctx.client("sts")
    cw = ctx.client("cloudwatch")
    ec2_caller = ctx.client("ec2")

    account = sts.get_caller_identity()["Account"]
    fis_trust = {
        "Effect": "Allow",
        "Principal": {"Service": "fis.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceAccount": account},
            "ArnLike": {"aws:SourceArn": f"arn:aws:fis:{ctx.region}:{account}:experiment/*"},
        },
    }

    # ---- the guardrail: an alarm forced to OK, which is FIS's documented precondition -----------
    alarm_name = ctx.unique_name("sim2real-g1-fisalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name, Namespace="Sim2RealFIS",
        MetricName=ctx.unique_name("sim2real-g1-metric-"), Statistic="Average", Period=60,
        EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
    # It starts as INSUFFICIENT_DATA, and FIS refuses a stop-condition alarm that is not OK at
    # StartExperiment. Making that precondition explicit is part of the claim.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK",
                       StateReason="sim2real g1 stop-condition rig setup")
    state_before = _alarm_state(cw, alarm_name)
    assert state_before == "OK", (
        f"the stop-condition alarm was {state_before!r} before StartExperiment; FIS requires 'OK'"
    )

    # ---- the same rig as the sibling check ------------------------------------------------------
    target_role = _create_role(
        ctx, iam,
        # The account root delegates to the account's own IAM policy, so the check's principal
        # can assume the role without the trust naming any particular caller.
        trust=[fis_trust, {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        actions=["ec2:DescribeAvailabilityZones", "ec2:DescribeRegions"])
    exec_role = _create_role(
        ctx, iam, trust=[fis_trust],
        # FIS evaluates an alarm stop condition USING THE EXPERIMENT ROLE, so it needs
        # cloudwatch:DescribeAlarms as well as the fault permission.
        actions=["fis:InjectApiInternalError", "cloudwatch:DescribeAlarms", "iam:GetRole",
                 "iam:ListRoles", "tag:GetResources"])

    template_id = _create_template(
        ctx, fis, role_arn=exec_role, alarm_arn=alarm_arn,
        targets={"roleTarget": {"resourceType": "aws:iam:role", "resourceArns": [target_role],
                                "selectionMode": "ALL"}},
        actions={"fault": {
            "actionId": "aws:fis:inject-api-internal-error",
            "parameters": {"duration": _ACTION_DURATION, "service": "ec2", "percentage": "100",
                           "operations": "DescribeAvailabilityZones"},
            "targets": {"Roles": "roleTarget"},
        }})

    role_creds = _assume(ctx, sts, target_role, timeout_s=_IAM_PROPAGATION_BUDGET_S)
    ec2_role = _no_retry_client(ctx, role_creds)
    baseline = _describe_azs_when_permitted(ec2_role, timeout_s=_IAM_PROPAGATION_BUDGET_S)
    assert len(baseline["AvailabilityZones"]) >= 3, (
        f"baseline returned {len(baseline['AvailabilityZones'])} AZs, not a real payload"
    )

    experiment_id = _start_experiment(ctx, fis, template_id)
    status = _poll_experiment(fis, experiment_id, {"running", "completed", "failed", "stopped"},
                              timeout_s=_EXPERIMENT_RUNNING_TIMEOUT_S)
    assert status == "running", f"experiment reached {status!r}, not 'running'"

    experiment = fis.get_experiment(id=experiment_id)["experiment"]
    # When the EXPERIMENT first reports state.status == 'running', the ACTION's own state can
    # still be {'status': 'pending', 'reason': 'Initial state.'} -- the two transition
    # independently, so poll it.
    action_status = _poll_action_status(fis, experiment_id, "running",
                                       timeout_s=_ACTION_RUNNING_TIMEOUT_S)
    if action_status != "running":
        now = fis.get_experiment(id=experiment_id)["experiment"]
        raise AssertionError(
            f"the action's own state settled at {action_status!r}, expected 'running'; "
            f"experiment state {now['state']!r}, action state {now['actions']['fault']['state']!r}"
        )
    condition_values = [c.get("value") for c in experiment["stopConditions"]]
    assert alarm_arn in condition_values, (
        f"the running experiment's stopConditions are {experiment['stopConditions']!r} -- they do "
        "not name our alarm, so an early stop could not be attributed to it"
    )

    # ---- the fault is LIVE --------------------------------------------------------------------
    err = _poll_for_injected_error(ec2_role, timeout_s=_FAULT_VISIBLE_TIMEOUT_S)
    assert err.response["Error"]["Code"] == _INJECTED_ERROR_CODE, (
        f"the injected failure reported {err.response['Error']['Code']!r}, expected "
        f"{_INJECTED_ERROR_CODE!r}"
    )
    assert err.response["Error"].get("Message") == _INJECTED_ERROR_MESSAGE, (
        f"the injected failure's message was {err.response['Error'].get('Message')!r}, expected "
        f"{_INJECTED_ERROR_MESSAGE!r}"
    )

    # ---- breach the guardrail. We never call StopExperiment. ------------------------------------
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM",
                       StateReason="sim2real g1 stop-condition breach trigger")
    final = _poll_experiment(fis, experiment_id, {"stopped", "completed", "failed"},
                             timeout_s=_AUTO_STOP_TIMEOUT_S)
    assert final == "stopped", (
        f"the experiment ended as {final!r} after the alarm breached, expected 'stopped' -- the "
        "service did not halt it, and this check made no StopExperiment call"
    )
    final_reason = fis.get_experiment(id=experiment_id)["experiment"]["state"].get("reason")
    assert final_reason == "Experiment halted by stop condition.", (
        f"the stopped experiment's reason was {final_reason!r}, expected "
        "'Experiment halted by stop condition.'"
    )

    # ---- and the fault ACTUALLY STOPPED ---------------------------------------------------------
    recovered = _poll_for_recovery(ec2_role, timeout_s=_RECOVERY_TIMEOUT_S)
    assert len(recovered["AvailabilityZones"]) >= 3, (
        f"the recovered call returned {len(recovered['AvailabilityZones'])} AZs, not a real payload"
    )

    final_action_status = _poll_action_status(fis, experiment_id, "stopped",
                                             timeout_s=_ACTION_RUNNING_TIMEOUT_S)
    assert final_action_status == "stopped", (
        f"the action's final state settled at {final_action_status!r}, expected 'stopped' -- it was "
        "allowed to FINISH rather than being halted"
    )
    stopped = fis.get_experiment(id=experiment_id)["experiment"]
    elapsed = (stopped["endTime"] - stopped["startTime"]).total_seconds()
    assert elapsed < _MAX_ATTRIBUTABLE_RECOVERY_S, (
        f"the experiment ran {elapsed:.1f}s of its {_ACTION_DURATION} ({_ACTION_DURATION_S}s) "
        f"duration before ending; anything at or above {_MAX_ATTRIBUTABLE_RECOVERY_S}s cannot be "
        "attributed to the stop condition rather than to the action expiring"
    )
    assert elapsed < _ACTION_DURATION_S, (
        f"the experiment ran {elapsed:.1f}s, i.e. its full {_ACTION_DURATION_S}s duration -- it "
        "expired, it was not halted"
    )
    action_reason = stopped["actions"]["fault"]["state"].get("reason")
    assert action_reason == "Action was stopped.", (
        f"the halted action's reason was {action_reason!r}, expected 'Action was stopped.'"
    )

    # ---- positive control: the guardrail did not break the account -------------------------------
    control = ec2_caller.describe_availability_zones()
    assert len(control["AvailabilityZones"]) >= 3, (
        f"the caller's own principal saw {len(control['AvailabilityZones'])} AZs -- the fault was never "
        "scoped to the targeted role"
    )

    # ---- verified inline teardown -----------------------------------------------------------------
    fis.delete_experiment_template(id=template_id)
    template_gone, gone_message = _error(lambda: fis.get_experiment_template(id=template_id))
    assert template_gone == "ResourceNotFoundException", (
        f"after DeleteExperimentTemplate, GetExperimentTemplate reported {template_gone!r}"
    )
    assert gone_message == "ExperimentTemplate not found.", (
        f"after DeleteExperimentTemplate, GetExperimentTemplate said {gone_message!r}, expected "
        "'ExperimentTemplate not found.'"
    )
    cw.delete_alarms(AlarmNames=[alarm_name])
    assert not cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"], (
        f"the alarm {alarm_name!r} still exists after DeleteAlarms"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"the call succeeded where an error was required: {result!r}")


def _alarm_state(cw, alarm_name):
    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert alarms, f"alarm {alarm_name!r} does not exist"
    return alarms[0]["StateValue"]


def _create_role(ctx, iam, trust, actions):
    name = ctx.unique_name("sim2real-g1-fisrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": trust}),
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = f"{name}-inline"
    iam.put_role_policy(RoleName=name, PolicyName=policy, PolicyDocument=json.dumps(
        {"Version": "2012-10-17",
         "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy))
    return arn


def _no_retry_client(ctx, creds):
    """A client signing as the TARGETED role that does NOT absorb the injected 500 into a retry, so
    recovery timing is the service's and not botocore's."""
    from botocore.config import Config

    return ctx.client(
        "ec2",
        config=Config(retries={"mode": "standard", "max_attempts": 0}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _assume(ctx, sts, role_arn, timeout_s):
    """Returns STS's own Credentials shape, untouched."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn,
                                   RoleSessionName="sim2real-g1-stopcond")["Credentials"]
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(f"could not assume {role_arn!r} within {timeout_s}s (last {last!r})")


def _describe_azs_when_permitted(client, timeout_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return client.describe_availability_zones()
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last != "UnauthorizedOperation":
                raise
            time.sleep(3)
    raise AssertionError(f"baseline call never became permitted in {timeout_s}s (last {last!r})")


def _create_template(ctx, fis, role_arn, alarm_arn, targets, actions, timeout_s=180.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            template_id = fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-g1-tok-"),
                description=ctx.unique_name("sim2real-g1-stopcond-"),
                stopConditions=[{"source": "aws:cloudwatch:alarm", "value": alarm_arn}],
                targets=targets, actions=actions, roleArn=role_arn,
                tags={"sim2real": "g1-fault-injection"})["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_quiet(fis, template_id))
            return template_id
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(f"CreateExperimentTemplate never succeeded in {timeout_s}s (last {last!r})")


def _delete_template_quiet(fis, template_id):
    from botocore.exceptions import ClientError

    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_experiment(ctx, fis, template_id, timeout_s=180.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            experiment_id = fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-g1-start-"),
                experimentTemplateId=template_id,
                tags={"sim2real": "g1-fault-injection"})["experiment"]["id"]
            ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))
            return experiment_id
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(4)
    raise AssertionError(f"StartExperiment never succeeded in {timeout_s}s (last {last!r})")


def _stop_experiment_quiet(fis, experiment_id):
    """The failure-path net ONLY. On the happy path the service stops this experiment itself, which
    is the whole subject of the check -- so nothing above ever calls StopExperiment."""
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _poll_experiment(fis, experiment_id, stop_on, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if last in stop_on:
            return last
        time.sleep(2)
    return last


def _poll_action_status(fis, experiment_id, want, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fis.get_experiment(
            id=experiment_id)["experiment"]["actions"]["fault"]["state"]["status"]
        if last == want:
            return last
        time.sleep(3)
    return last


def _poll_for_injected_error(client, timeout_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_availability_zones()
        except ClientError as err:
            return err
        time.sleep(2)
    raise AssertionError(
        f"the experiment reported 'running' but the targeted call kept returning 200 for "
        f"{timeout_s}s -- there was no fault for the stop condition to halt"
    )


def _poll_for_recovery(client, timeout_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return client.describe_availability_zones()
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(
        f"the targeted call was still failing {timeout_s}s after the experiment reached 'stopped' "
        f"(last {last!r}) -- the stop condition changed a status field and left the fault running, "
        "which is exactly the blast-radius guardrail that only ever changed a string"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
