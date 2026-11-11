"""obs-lambda-3-duplicate-permission-rejected-and-audited."""

# CloudTrail names AddPermission by its API-version-suffixed eventName "AddPermission20150331v2".

from __future__ import annotations

import datetime
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-lambda-3-duplicate-permission-rejected-and-audited"
GROUP = "eventing"
SERVICES = ["cloudtrail", "lambda"]

_EVENT_SOURCE = "lambda.amazonaws.com"
_PERMISSION_EVENT = "AddPermission20150331v2"

_INDEX_BUDGET_S = 420.0
_ROLE_PROPAGATION_BUDGET_S = 90.0
_ACTIVE_BUDGET_S = 90.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# ===== helpers =====


def _error_code(fn):
    """The AWS error code `fn` raised. RAISES if `fn` succeeds -- success is the strongest signal."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _create_role(ctx, iam):
    """An execution role with NO permission policy: nothing here invokes, and without logs:* the
    function cannot create a /aws/lambda/<fn> log group that would outlive it."""
    name = ctx.unique_name("sim2real-xsvc-ctl-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=name)))
    return arn


def _create_function(ctx, lam, logs, name, **kwargs):
    """CreateFunction, retrying ONLY through the IAM propagation window of a brand-new role."""
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"))
    )
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            resp = lam.create_function(FunctionName=name, **kwargs)
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message") or ""
            if "cannot be assumed" not in msg or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lam.delete_function(FunctionName=name)))
    deadline = time.monotonic() + _ACTIVE_BUDGET_S
    while lam.get_function_configuration(FunctionName=name).get("State") != "Active":
        if time.monotonic() >= deadline:
            raise AssertionError(f"function {name} not Active within {_ACTIVE_BUDGET_S:.0f}s")
        time.sleep(2.0)
    return resp


def _lookup_all(ct, **kw):
    out = []
    for _ in range(_PAGE_CEILING):
        resp = ct.lookup_events(**kw)
        out.extend(resp.get("Events", []))
        token = resp.get("NextToken")
        if not token:
            return out
        kw["NextToken"] = token
    raise AssertionError(f"LookupEvents paged past {_PAGE_CEILING} pages without exhausting")


def _policy_statements(lam, fn_name):
    return json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])["Statement"]


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "cap:c2",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A second AddPermission reusing a StatementId is rejected with ResourceConflictException and
    leaves the policy unchanged, and CloudTrail records that rejected write with its errorCode
    beside the two successful AddPermission20150331v2 records.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    ct = ctx.client("cloudtrail")

    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    fn_name = ctx.unique_name("sim2real-xsvc-ctl-fn-")
    sid = "sim2real-" + uuid.uuid4().hex[:12]
    control_sid = "sim2real-" + uuid.uuid4().hex[:12]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def lambda_handler(event, context):\n    return 'ok'\n")

    role_arn = _create_role(ctx, iam)
    created = _create_function(
        ctx,
        lam,
        logs,
        fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": buf.getvalue()},
        Description=f"sim2real {CHECK}",
        Tags={"sim2real": CHECK},
    )

    lam.add_permission(
        FunctionName=fn_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceAccount=account_id,
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: lam.remove_permission(FunctionName=fn_name, StatementId=sid))
    )
    before = _policy_statements(lam, fn_name)
    assert [s["Sid"] for s in before] == [sid], (
        f"after one AddPermission the policy must hold exactly that statement: expected [{sid!r}], "
        f"actual {[s['Sid'] for s in before]!r}"
    )

    # ---- the one broken thing: reuse the StatementId with a different principal --------------------
    code, resp = _error_code(
        lambda: lam.add_permission(
            FunctionName=fn_name,
            StatementId=sid,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
        )
    )
    assert code == "ResourceConflictException", (
        f"AddPermission with a duplicate StatementId: expected ResourceConflictException, actual {code!r}"
    )
    want_conflict = (
        f"The statement id ({sid}) provided already exists. Please provide a new statement id, or "
        "remove the existing statement."
    )
    got_conflict = resp.get("Error", {}).get("Message")
    assert got_conflict == want_conflict, (
        f"duplicate StatementId message: expected {want_conflict!r}, actual {got_conflict!r}"
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 409, (
        f"duplicate StatementId: expected HTTP 409, actual {resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    after = _policy_statements(lam, fn_name)
    assert after == before, (
        "a rejected AddPermission must leave the resource policy byte-for-byte unchanged: expected "
        f"{before!r}, actual {after!r}"
    )
    assert "sns.amazonaws.com" not in json.dumps(after), (
        f"the rejected principal must not appear in the policy: actual {after!r}"
    )

    # ---- positive control: a fresh StatementId on the same function still succeeds ----------------
    lam.add_permission(
        FunctionName=fn_name,
        StatementId=control_sid,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceAccount=account_id,
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: lam.remove_permission(FunctionName=fn_name, StatementId=control_sid)
        )
    )
    sids = sorted(s["Sid"] for s in _policy_statements(lam, fn_name))
    assert sids == sorted([sid, control_sid]), (
        f"the control AddPermission must add its statement: expected {sorted([sid, control_sid])!r}, "
        f"actual {sids!r}"
    )

    # ---- the terminal read: CloudTrail event history ----------------------------------------------
    def _wanted(records):
        ok = [r for r in records if r.get("errorCode") is None]
        failed = [r for r in records if r.get("errorCode") is not None]
        ok_sids = sorted((r.get("requestParameters") or {}).get("statementId") or "" for r in ok)
        return ok, failed, ok_sids

    records: list[dict] = []
    names_seen: set[str] = set()
    deadline = time.monotonic() + _INDEX_BUDGET_S
    while True:
        records = []
        for ev in _lookup_all(
            ct,
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": fn_name}],
            StartTime=start,
        ):
            rec = json.loads(ev["CloudTrailEvent"])
            names_seen.add(rec.get("eventName"))
            if rec.get("eventName") == _PERMISSION_EVENT:
                records.append(rec)
        ok, failed, ok_sids = _wanted(records)
        if failed and set(ok_sids) >= {sid, control_sid}:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"within {_INDEX_BUDGET_S:.0f}s CloudTrail must index two successful and one rejected "
                f"{_PERMISSION_EVENT!r} for {fn_name!r}: actual successful statementIds {ok_sids!r}, "
                f"rejected {len(failed)}, eventNames seen {sorted(n for n in names_seen if n)!r}"
            )
        time.sleep(_POLL_INTERVAL_S)

    for rec in failed:
        assert rec.get("errorCode") == "ResourceConflictException", (
            f"the rejected AddPermission's errorCode: expected 'ResourceConflictException', actual "
            f"{rec.get('errorCode')!r}"
        )
    rejected = failed[0]
    params = rejected.get("requestParameters") or {}
    assert params.get("statementId") == sid and params.get("principal") == "sns.amazonaws.com", (
        "the rejected record must carry the REJECTED request (duplicate sid, sns principal): actual "
        f"statementId={params.get('statementId')!r} principal={params.get('principal')!r}"
    )
    assert params.get("functionName") == fn_name, (
        f"requestParameters.functionName: expected {fn_name!r}, actual {params.get('functionName')!r}"
    )
    assert rejected.get("errorMessage") == want_conflict, (
        f"the rejected record's errorMessage must be the message the caller received: expected "
        f"{want_conflict!r}, actual {rejected.get('errorMessage')!r}"
    )
    assert rejected.get("readOnly") is False, (
        f"a rejected WRITE is still a write: expected readOnly False, actual {rejected.get('readOnly')!r}"
    )
    assert rejected.get("responseElements") is None, (
        f"a rejected call has no response elements: expected None, actual {rejected.get('responseElements')!r}"
    )
    assert rejected.get("eventSource") == _EVENT_SOURCE, (
        f"eventSource: expected {_EVENT_SOURCE!r}, actual {rejected.get('eventSource')!r}"
    )
    for rec in ok:
        assert "sns.amazonaws.com" not in json.dumps(rec.get("requestParameters")), (
            f"a successful record must not carry the rejected principal: actual {rec!r}"
        )
        assert rec.get("responseElements") is not None, (
            "a successful AddPermission record must carry the granted statement in responseElements: "
            f"actual {rec.get('responseElements')!r}"
        )
    assert created["FunctionArn"] in json.dumps([r.get("responseElements") for r in ok]), (
        f"the granted statements must name the function ARN {created['FunctionArn']!r} as Resource"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
