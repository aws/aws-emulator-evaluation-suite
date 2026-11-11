"""lookup-events-records-a-denied-call-with-errorcode-and-correlates-the-sdk-request-id."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lookup-events-records-a-denied-call-with-errorcode-and-correlates-the-sdk-request-id"
GROUP = "data-plane"
SERVICES = ["cloudtrail"]

# Carried in the failure detail when a rejection is never audited, so the miss is graded as a
# data-plane FAIL rather than dropping out of the denominator.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# LookupEvents indexes a denied call on the same timeline as an allowed one, typically within
# 100-135 s; the budget leaves headroom over that.
_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# The SDK raises AccessDeniedException while CloudTrail records errorCode "AccessDenied"; the two
# are NOT the same string, so both are asserted separately.
_SDK_CODE = "AccessDeniedException"
_AUDIT_CODE = "AccessDenied"


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded); never assert membership in one page."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM-denied logs:DescribeLogGroups is audited in LookupEvents with errorCode AccessDenied,
    an errorMessage naming action and role, null requestParameters/responseElements, the assumed
    role's identity, and a requestID byte-identical to the SDK's; an allowed call is the control.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
    """
    ct = ctx.client("cloudtrail")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    logs = ctx.client("logs")
    account = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-f4denied-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav CloudTrail denied-call audit scenario",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _delete_role(_n=role_name):
        for pname in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=_n, PolicyName=pname)
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)

    # The one thing this principal may do is sts:GetCallerIdentity. Nothing is denied
    # explicitly, so the denial under test is IAM's implicit one -- the shape a real caller
    # hits.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-only-get-caller-identity",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity",
                           "Resource": "*"}],
        }),
    )

    # A freshly created role is eventually consistent and exposes no condition to poll, so
    # AssumeRole is retried past AccessDenied rather than slept over.
    session_name = "sim2real-behav-f4denied"
    creds = None
    last_assume = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName=session_name,
            )["Credentials"]
            break
        except ClientError as err:
            last_assume = err
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly created role {role_name!r} never succeeded within 90s, so "
        f"the denial could not be provoked: {last_assume!r}"
    )

    # ctx.client's re-signing idiom keeps THIS target's endpoint while signing with the assumed
    # role's temporary credentials; a hand-rolled botocore session would always resolve AWS's own
    # endpoints.
    limited = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # --- The denied call. Emitted as early as possible so the indexing wait overlaps the rest.
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    denied_group = ctx.unique_name("sim2real-behav-f4dg-")
    try:
        limited.describe_log_groups(logGroupNamePrefix=denied_group)
        raise AssertionError(
            f"logs:DescribeLogGroups SUCCEEDED for a principal whose only permission is "
            f"sts:GetCallerIdentity. There is no denial to audit, and the target is "
            f"over-permissive: role {role_name!r} carries one inline policy granting "
            f"sts:GetCallerIdentity alone."
        )
    except ClientError as err:
        sdk_code = err.response["Error"]["Code"]
        sdk_message = err.response["Error"]["Message"]
        sdk_request_id = err.response["ResponseMetadata"]["RequestId"]
    assert sdk_code == _SDK_CODE, (
        f"the SDK reported error code {sdk_code!r} for the denied logs:DescribeLogGroups, "
        f"expected {_SDK_CODE!r}"
    )
    assert sdk_message == f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name} is not authorized to perform: logs:DescribeLogGroups on resource: arn:aws:logs:{ctx.region}:{ctx.account}:log-group::log-stream: because no identity-based policy allows the logs:DescribeLogGroups action", (
        f"expected the exact AccessDeniedException message AWS returns, got {sdk_message!r}"
    )
    assert sdk_request_id, (
        "the denied call's response carried no ResponseMetadata.RequestId, so there is nothing "
        "to correlate the audit record against"
    )

    # --- The positive control: the SAME service, the SAME region, a call that is allowed.
    control_group = ctx.unique_name("sim2real-behav-f4cg-")
    control_response = logs.create_log_group(logGroupName=control_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=control_group))
    control_request_id = control_response["ResponseMetadata"]["RequestId"]

    window_start = emitted_at - datetime.timedelta(minutes=3)
    denied_record = denied_envelope = None
    control_record = control_envelope = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        now = datetime.datetime.now(datetime.timezone.utc)
        for event_name in ("DescribeLogGroups", "CreateLogGroup"):
            events = _lookup_all(
                ct, StartTime=window_start, EndTime=now + datetime.timedelta(minutes=5),
                MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName",
                                   "AttributeValue": event_name}],
            )
            scanned += len(events)
            for ev in events:
                raw = ev.get("CloudTrailEvent", "")
                if event_name == "DescribeLogGroups":
                    # requestParameters is null on a denied call, so the record is located by the
                    # run-unique role name instead, which keeps the requestID join non-circular.
                    if denied_record is None and role_name in raw:
                        denied_envelope, denied_record = ev, json.loads(raw)
                elif control_record is None and control_group in raw:
                    control_envelope, control_record = ev, json.loads(raw)
        if denied_record is not None and control_record is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert denied_record is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail produced no audit record for an API call it REFUSED. A "
        f"logs:DescribeLogGroups by assumed role {role_name!r} was denied at "
        f"{emitted_at.isoformat()} with {sdk_code} (SDK request id {sdk_request_id}); {polls} "
        f"LookupEvents polls over {waited:.0f}s scanned {scanned} events in the window and none "
        f"named that role. Real AWS indexed the same rejection within 100s. A target that "
        f"audits only successful dispatch has wired its authorization decision and its audit "
        f"pipeline together on one path and not the other."
    )
    assert control_record is not None, (
        f"{DATAPLANE_MARKER}: the ALLOWED control call was never audited either -- "
        f"logs:CreateLogGroup for {control_group!r} is absent from LookupEvents after "
        f"{waited:.0f}s and {polls} polls. Without it the denial assertions cannot be shown to "
        f"be about the denial rather than about the target auditing nothing."
    )

    # --- The rejection is audited as a rejection.
    assert denied_record["errorCode"] == _AUDIT_CODE, (
        f"the audit record for the denied call carries errorCode "
        f"{denied_record.get('errorCode')!r}, expected {_AUDIT_CODE!r}. MEASURED: the audit "
        f"code is IAM's ({_AUDIT_CODE}), not the service exception name the SDK raised "
        f"({_SDK_CODE}) -- a target that echoes the SDK code into the record fails here"
    )
    assert "logs:DescribeLogGroups" in denied_record["errorMessage"], (
        f"errorMessage must name the action that was denied; got "
        f"{denied_record.get('errorMessage')!r}"
    )
    assert role_name in denied_record["errorMessage"], (
        f"errorMessage must name the principal that was denied; got "
        f"{denied_record.get('errorMessage')!r}, which does not mention {role_name!r}"
    )

    # --- The join. The record was located by the role name, so this is not circular.
    assert denied_record["requestID"] == sdk_request_id, (
        f"the audit record's requestID {denied_record.get('requestID')!r} is not the request id "
        f"botocore observed on the failed call ({sdk_request_id!r}). One request id is minted "
        f"once and must surface both in the SDK response and, minutes later, in a different "
        f"service's index; a target that generates ids per response cannot make them equal, and "
        f"'find the trace for this failed call' is exactly this join"
    )

    # --- Effect absent: a refused call produced no response and touched no resource.
    assert denied_record["requestParameters"] is None, (
        f"requestParameters is {denied_record['requestParameters']!r} on a DENIED call; "
        f"MEASURED on real AWS it is null, because the request was rejected before its "
        f"arguments were accepted"
    )
    assert denied_record["responseElements"] is None, (
        f"responseElements is {denied_record['responseElements']!r} on a denied call -- there "
        f"was no response to record. A target templating a success shape fails here"
    )
    assert denied_envelope["Resources"] == [], (
        f"the LookupEvents envelope for the denied call reports Resources "
        f"{denied_envelope['Resources']!r}; a refused call touched nothing"
    )

    # --- The denial is attributed to the assumed role, not to the base principal.
    assert denied_record["userIdentity"]["type"] == "AssumedRole", (
        f"userIdentity.type is {denied_record['userIdentity'].get('type')!r}, expected "
        f"AssumedRole"
    )
    assert (denied_record["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"]
            == role_name), (
        f"userIdentity.sessionContext.sessionIssuer.userName is "
        f"{denied_record['userIdentity']['sessionContext']['sessionIssuer'].get('userName')!r}, "
        f"expected the role this check created ({role_name!r})"
    )
    assert denied_record["userIdentity"]["arn"] == (
        f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"
    ), (
        f"userIdentity.arn is {denied_record['userIdentity'].get('arn')!r}, expected the "
        f"assumed-role session ARN arn:aws:sts::{account}:assumed-role/{role_name}/"
        f"{session_name}"
    )
    assert denied_envelope["Username"] == session_name, (
        f"the envelope's Username is {denied_envelope.get('Username')!r}, expected the role "
        f"session name {session_name!r}"
    )

    # --- readOnly is a property of the OPERATION, not of the outcome.
    assert denied_record["readOnly"] is True, (
        f"readOnly is {denied_record.get('readOnly')!r} for a DENIED DescribeLogGroups. The "
        f"classification belongs to the operation, so a target that derives it from 'did this "
        f"mutate anything' gets a denied read wrong"
    )
    assert denied_envelope["ReadOnly"] == "true", (
        f"the envelope's ReadOnly member is stringly typed and must be exactly 'true'; got "
        f"{denied_envelope.get('ReadOnly')!r}"
    )
    assert denied_record["eventSource"] == "logs.amazonaws.com", (
        f"eventSource is {denied_record.get('eventSource')!r}, expected logs.amazonaws.com"
    )
    assert denied_record["eventName"] == "DescribeLogGroups", (
        f"eventName is {denied_record.get('eventName')!r}, expected DescribeLogGroups"
    )
    assert denied_record["managementEvent"] is True, (
        f"managementEvent is {denied_record.get('managementEvent')!r}, expected True"
    )
    assert denied_record["awsRegion"] == ctx.region, (
        f"awsRegion is {denied_record.get('awsRegion')!r}, expected {ctx.region!r}"
    )
    assert denied_envelope["EventId"] == denied_record["eventID"], (
        f"the envelope's EventId {denied_envelope['EventId']!r} disagrees with the embedded "
        f"record's eventID {denied_record.get('eventID')!r} -- a target that synthesises the "
        f"two independently disagrees here even when each looks plausible"
    )

    # --- Positive control: the allowed call is audited as a success, and joins its own id.
    assert "errorCode" not in control_record, (
        f"the ALLOWED logs:CreateLogGroup record carries errorCode "
        f"{control_record.get('errorCode')!r}; a successful call has no error, so the denied "
        f"record's errorCode is not something this target attaches to everything"
    )
    assert control_record["requestParameters"] == {"logGroupName": control_group}, (
        f"the allowed call's requestParameters is "
        f"{control_record.get('requestParameters')!r}, expected "
        f"{{'logGroupName': {control_group!r}}} -- this is the measured discriminator against "
        f"the denied record's null, so a target that always records arguments, or never does, "
        f"fails one of the two"
    )
    assert control_record["requestID"] == control_request_id, (
        f"the allowed call's audit requestID {control_record.get('requestID')!r} is not the id "
        f"botocore observed ({control_request_id!r}); without this the denied call's join could "
        f"be passing by coincidence"
    )
    assert control_record["readOnly"] is False, (
        f"readOnly is {control_record.get('readOnly')!r} for CreateLogGroup, which is a write"
    )
    assert [r["ResourceName"] for r in control_envelope["Resources"]] == [control_group], (
        f"the allowed call's envelope reports Resources "
        f"{control_envelope.get('Resources')!r}, expected exactly the log group it created "
        f"({control_group!r}) -- the contrast with the denied call's empty Resources is the "
        f"effect-absent probe"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
