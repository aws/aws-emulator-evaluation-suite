"""obs-sfn-2-lookup-events-audits-start-execution-and-a-rejected-describe-state-machine."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-2-lookup-events-audits-start-execution-and-a-rejected-describe-state-machine"
GROUP = "eventing"
SERVICES = ["cloudtrail", "stepfunctions"]

# A failure detail containing this string is graded as a behavioral fail, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# LookupEvents indexes a call roughly 80-135 s after it is made; this bound leaves wide headroom.
_LOOKUP_BUDGET_S = 900.0
# Once any record of this run is indexed, this long with nothing new means the index froze.
_STALL_WAIT_S = 420.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
_IAM_RETRY_DEADLINE_S = 90.0

_EVENT_SOURCE = "states.amazonaws.com"
# The SDK error code and the record's errorCode are the same string for this service-side
# rejection (unlike an IAM denial, where they differ).
_MISSING_CODE = "StateMachineDoesNotExist"

_DEFINITION = {
    "Comment": "sim2real cloudtrail__sfn audit subject",
    "StartAt": "Echo",
    "States": {"Echo": {"Type": "Pass", "End": True}},
}


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CloudTrail LookupEvents audits StartExecution and a rejected and a successful
    DescribeStateMachine from one assumed-role session: identity, request ids, readOnly, and an
    errorCode/errorMessage matching the SDK only on the rejected call."""
    ct = ctx.client("cloudtrail")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sfn = ctx.client("stepfunctions")
    account = sts.get_caller_identity()["Account"]

    exec_role_arn = _create_execution_role(ctx, iam)
    sm_arn = _create_state_machine(ctx, sfn, exec_role_arn)

    # The caller role: everything audited below is made through a session of THIS role, so the
    # record's userIdentity can be held to an ARN this run minted.
    caller_role = ctx.unique_name("sim2real-xsvc-ctsfn-caller-")
    caller_role_arn = iam.create_role(
        RoleName=caller_role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-xsvc cloudtrail__sfn audited caller",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, caller_role))
    iam.put_role_policy(
        RoleName=caller_role,
        PolicyName="sim2real-xsvc-ctsfn-caller",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["states:StartExecution", "states:DescribeStateMachine",
                                      "states:DescribeExecution"],
                           "Resource": "*"}],
        }),
    )
    # IAM propagation is per action with no pollable condition, so a separate, unaudited warm-up
    # session waits until all three actions authorize before the audited session is created.
    _warm_up(ctx, sts, caller_role_arn, sm_arn)

    session_name = ctx.unique_name("sim2real-ctsfn-")[:64]
    assumed = _assume_with_retry(sts, caller_role_arn, session_name)
    assumed_arn = assumed["AssumedRoleUser"]["Arn"]
    assert assumed_arn == f"arn:aws:sts::{account}:assumed-role/{caller_role}/{session_name}", (
        f"AssumeRole returned AssumedRoleUser.Arn {assumed_arn!r}, expected "
        f"arn:aws:sts::{account}:assumed-role/{caller_role}/{session_name}"
    )
    caller_sfn = _session_client(ctx, assumed["Credentials"])

    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=3)

    # ---- the successful write. Inline policy propagation has no pollable condition, so the first
    # use of the permission is retried past AccessDenied (bounded) rather than slept over.
    exec_name = ctx.unique_name("sim2real-ctsfn-exec-")[:80]
    started = _call_with_iam_retry(
        lambda: caller_sfn.start_execution(
            stateMachineArn=sm_arn, name=exec_name, input=json.dumps({"probe": exec_name})))
    ctx.on_cleanup(lambda: _stop_execution(sfn, started["executionArn"]))
    exec_arn = started["executionArn"]
    start_request_id = started["ResponseMetadata"]["RequestId"]
    final = _wait_terminal(sfn, exec_arn)
    assert final["status"] == "SUCCEEDED", (
        f"the audited execution must actually run: expected SUCCEEDED, actual {final['status']!r} "
        f"({final!r})"
    )
    assert json.loads(final["output"]) == {"probe": exec_name}, (
        f"the Pass state must echo its input: expected {{'probe': {exec_name!r}}}, actual "
        f"{final.get('output')!r}"
    )

    # ---- the rejected read: an ARN shaped exactly like the real one, naming a machine that
    # does not exist.
    missing_arn = sm_arn.rsplit(":", 1)[0] + ":" + ctx.unique_name("sim2real-ctsfn-missing-")
    try:
        unexpected = caller_sfn.describe_state_machine(stateMachineArn=missing_arn)
        raise AssertionError(
            f"DescribeStateMachine on a state machine that was never created SUCCEEDED: "
            f"{missing_arn!r} -> {unexpected!r}; there is no rejection to audit and the target "
            f"is over-permissive"
        )
    except ClientError as err:
        missing_sdk_code = err.response["Error"]["Code"]
        missing_sdk_message = err.response["Error"]["Message"]
        missing_request_id = err.response["ResponseMetadata"]["RequestId"]
    assert missing_sdk_code == _MISSING_CODE, (
        f"DescribeStateMachine on a missing ARN: expected error {_MISSING_CODE!r}, actual "
        f"{missing_sdk_code!r} ({missing_sdk_message!r})"
    )
    want_missing_message = f"State Machine Does Not Exist: '{missing_arn}'"
    assert missing_sdk_message == want_missing_message, (
        f"DescribeStateMachine on a missing ARN message: expected {want_missing_message!r}, actual "
        f"{missing_sdk_message!r}"
    )

    # ---- positive control: the same operation, same session, on the real machine.
    described = _call_with_iam_retry(
        lambda: caller_sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert described["stateMachineArn"] == sm_arn and described["status"] == "ACTIVE", (
        f"the control DescribeStateMachine must succeed on the real machine: expected arn "
        f"{sm_arn!r} ACTIVE, actual {described.get('stateMachineArn')!r} "
        f"{described.get('status')!r}"
    )
    describe_request_id = described["ResponseMetadata"]["RequestId"]

    # ---- poll the event history -----------------------------------------------------------
    found: dict[str, tuple[dict, dict]] = {}
    seen_ids: set[str] = set()
    t0 = time.monotonic()
    last_progress = None
    polls = 0
    while True:
        polls += 1
        now = datetime.datetime.now(datetime.timezone.utc)
        for event_name in ("StartExecution", "DescribeStateMachine"):
            for env in _lookup_all(ct, StartTime=window_start,
                                   EndTime=now + datetime.timedelta(minutes=5),
                                   LookupAttributes=[{"AttributeKey": "EventName",
                                                      "AttributeValue": event_name}]):
                record = json.loads(env.get("CloudTrailEvent") or "{}")
                if (record.get("userIdentity") or {}).get("arn") != assumed_arn:
                    continue
                if env["EventId"] not in seen_ids:
                    seen_ids.add(env["EventId"])
                    last_progress = time.monotonic()
                arn = (record.get("requestParameters") or {}).get("stateMachineArn")
                if event_name == "StartExecution" and arn == sm_arn:
                    found.setdefault("start", (env, record))
                elif event_name == "DescribeStateMachine" and arn == missing_arn:
                    found.setdefault("missing", (env, record))
                elif event_name == "DescribeStateMachine" and arn == sm_arn:
                    found.setdefault("control", (env, record))
        if len(found) == 3:
            break
        elapsed = time.monotonic() - t0
        frozen = last_progress is not None and time.monotonic() - last_progress >= _STALL_WAIT_S
        if elapsed >= _LOOKUP_BUDGET_S or frozen:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: CloudTrail event history did not index every Step Functions "
                f"call this session made: expected records 'start', 'missing', 'control', actual "
                f"{sorted(found)!r} after {elapsed:.0f}s and {polls} polls; "
                f"{len(seen_ids)} record(s) attributed to {assumed_arn!r} were seen"
                + (f"; the index FROZE (nothing new for {_STALL_WAIT_S:.0f}s)" if frozen else "")
            )
        time.sleep(_POLL_INTERVAL_S)

    # ---- the rejected call ----------------------------------------------------------------
    m_env, m = found["missing"]
    assert m["eventSource"] == _EVENT_SOURCE, (
        f"rejected record eventSource: expected {_EVENT_SOURCE!r}, actual {m.get('eventSource')!r}"
    )
    assert m["eventName"] == "DescribeStateMachine", (
        f"rejected record eventName: expected 'DescribeStateMachine', actual {m.get('eventName')!r}"
    )
    assert m.get("errorCode") == _MISSING_CODE, (
        f"rejected record errorCode: expected {_MISSING_CODE!r} (the code the SDK saw), actual "
        f"{m.get('errorCode')!r}"
    )
    assert m.get("errorMessage") == missing_sdk_message, (
        f"rejected record errorMessage must be the message the caller received: expected "
        f"{missing_sdk_message!r}, actual {m.get('errorMessage')!r}"
    )
    assert missing_arn in (m.get("errorMessage") or ""), (
        f"rejected record errorMessage must name the missing ARN {missing_arn!r}: actual "
        f"{m.get('errorMessage')!r}"
    )
    assert m.get("responseElements") is None, (
        f"a rejected call has no response to record: expected responseElements None, actual "
        f"{m.get('responseElements')!r}"
    )
    assert m.get("requestParameters") == {"stateMachineArn": missing_arn}, (
        f"rejected record requestParameters: expected {{'stateMachineArn': {missing_arn!r}}}, "
        f"actual {m.get('requestParameters')!r} -- a service-side rejection still records the "
        f"arguments it was given"
    )
    assert m.get("requestID") == missing_request_id, (
        f"rejected record requestID {m.get('requestID')!r} is not the request id the SDK observed "
        f"on the failed call ({missing_request_id!r})"
    )
    assert m.get("readOnly") is True and m_env.get("ReadOnly") == "true", (
        f"DescribeStateMachine is a read even when rejected: expected readOnly True / envelope "
        f"'true', actual {m.get('readOnly')!r} / {m_env.get('ReadOnly')!r}"
    )
    assert m_env["EventId"] == m.get("eventID"), (
        f"envelope EventId {m_env['EventId']!r} disagrees with the record's eventID "
        f"{m.get('eventID')!r}"
    )

    # ---- identity, on all three -------------------------------------------------------------
    for label, (env, rec) in sorted(found.items()):
        ui = rec.get("userIdentity") or {}
        assert ui.get("type") == "AssumedRole", (
            f"[{label}] userIdentity.type: expected 'AssumedRole', actual {ui.get('type')!r}"
        )
        assert ui.get("arn") == assumed_arn, (
            f"[{label}] userIdentity.arn: expected the session ARN {assumed_arn!r}, actual "
            f"{ui.get('arn')!r}"
        )
        issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
        assert issuer.get("arn") == caller_role_arn, (
            f"[{label}] sessionIssuer.arn: expected {caller_role_arn!r}, actual "
            f"{issuer.get('arn')!r}"
        )
        assert env.get("Username") == session_name, (
            f"[{label}] envelope Username: expected the session name {session_name!r}, actual "
            f"{env.get('Username')!r}"
        )
        assert rec.get("eventSource") == _EVENT_SOURCE and env.get("EventSource") == _EVENT_SOURCE, (
            f"[{label}] eventSource: expected {_EVENT_SOURCE!r}, actual record "
            f"{rec.get('eventSource')!r} / envelope {env.get('EventSource')!r}"
        )
        assert rec.get("awsRegion") == ctx.region, (
            f"[{label}] awsRegion: expected {ctx.region!r}, actual {rec.get('awsRegion')!r}"
        )
        assert rec.get("recipientAccountId") == account, (
            f"[{label}] recipientAccountId: expected {account!r}, actual "
            f"{rec.get('recipientAccountId')!r}"
        )
        assert rec.get("eventCategory") == "Management", (
            f"[{label}] eventCategory: expected 'Management', actual {rec.get('eventCategory')!r}"
        )

    # ---- the successful write ---------------------------------------------------------------
    _s_env, s = found["start"]
    assert "errorCode" not in s and "errorMessage" not in s, (
        f"the successful StartExecution record must carry no error: errorCode "
        f"{s.get('errorCode')!r}, errorMessage {s.get('errorMessage')!r}"
    )
    assert s["eventName"] == "StartExecution", (
        f"start record eventName: expected 'StartExecution', actual {s.get('eventName')!r}"
    )
    assert (s.get("requestParameters") or {}).get("stateMachineArn") == sm_arn, (
        f"start record requestParameters.stateMachineArn: expected {sm_arn!r}, actual "
        f"{(s.get('requestParameters') or {}).get('stateMachineArn')!r}"
    )
    assert (s.get("requestParameters") or {}).get("name") == exec_name, (
        f"start record requestParameters.name: expected {exec_name!r}, actual "
        f"{(s.get('requestParameters') or {}).get('name')!r}"
    )
    assert (s.get("responseElements") or {}).get("executionArn") == exec_arn, (
        f"start record responseElements.executionArn must be the ARN the SDK was handed "
        f"({exec_arn!r}); actual {s.get('responseElements')!r}"
    )
    assert s.get("requestID") == start_request_id, (
        f"start record requestID {s.get('requestID')!r} is not the SDK's {start_request_id!r}"
    )
    assert s.get("readOnly") is False, (
        f"StartExecution is a write: expected readOnly False, actual {s.get('readOnly')!r}"
    )

    # ---- the control read: same operation as the rejection, no error -------------------------
    _c_env, c = found["control"]
    assert "errorCode" not in c and "errorMessage" not in c, (
        f"the successful DescribeStateMachine record must carry no error -- this is what makes the "
        f"rejected record's errorCode about the rejection: errorCode {c.get('errorCode')!r}"
    )
    assert c.get("requestID") == describe_request_id, (
        f"control record requestID {c.get('requestID')!r} is not the SDK's "
        f"{describe_request_id!r}"
    )
    assert c.get("readOnly") is True, (
        f"control DescribeStateMachine readOnly: expected True, actual {c.get('readOnly')!r}"
    )


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded), riding out LookupEvents' 2 TPS account limit."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        for attempt in range(6):
            try:
                resp = ct.lookup_events(MaxResults=50, **kw)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or attempt == 5:
                    raise
                time.sleep(2.0 * (attempt + 1))
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _create_execution_role(ctx, iam):
    """A states.amazonaws.com-assumable role with no permissions: a Pass state calls nothing."""
    name = ctx.unique_name("sim2real-xsvc-ctsfn-exec-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "states.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-xsvc cloudtrail__sfn execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return arn


def _delete_role(iam, name):
    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


def _create_state_machine(ctx, sfn, role_arn):
    """CreateStateMachine, retrying the AccessDeniedException a not-yet-assumable role produces."""
    name = ctx.unique_name("sim2real-xsvc-ctsfn-sm-")
    deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(_DEFINITION), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _session_client(ctx, creds):
    return ctx.client("stepfunctions", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _warm_up(ctx, sts, role_arn, sm_arn):
    """Until each audited action stops answering AccessDeniedException, from a throwaway session."""
    warm = _session_client(
        ctx, _assume_with_retry(sts, role_arn, ctx.unique_name("sim2real-ctsfn-warm-"))[
            "Credentials"])
    base = sm_arn.rsplit(":", 1)[0]
    ghost_sm = base + ":" + ctx.unique_name("sim2real-ctsfn-warm-")
    ghost_exec = base.replace(":stateMachine", ":execution") + ":" + ghost_sm.rsplit(":", 1)[1] + ":x"
    probes = [
        (lambda: warm.start_execution(stateMachineArn=ghost_sm), "StateMachineDoesNotExist"),
        (lambda: warm.describe_state_machine(stateMachineArn=ghost_sm), "StateMachineDoesNotExist"),
        (lambda: warm.describe_execution(executionArn=ghost_exec), "ExecutionDoesNotExist"),
    ]
    for fn, want in probes:
        deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
        while True:
            try:
                fn()
                raise AssertionError(f"a warm-up probe on a missing ARN succeeded; expected {want}")
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
            if code == want:
                break
            assert code == "AccessDeniedException" and time.monotonic() < deadline, (
                f"warm-up probe: expected {want!r} once the caller role's policy is effective, "
                f"actual {code!r}"
            )
            time.sleep(3.0)


def _assume_with_retry(sts, role_arn, session_name):
    deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"AssumeRole on the fresh caller role never succeeded: {last!r}")


def _call_with_iam_retry(fn):
    """First use of a freshly attached inline policy: retry past AccessDeniedException only."""
    deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"the caller role's inline policy never took effect: {last!r}")


def _wait_terminal(sfn, exec_arn, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _stop_execution(sfn, exec_arn):
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
