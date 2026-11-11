"""obs-lambda-3-management-events."""

from __future__ import annotations

import base64
import datetime
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-lambda-3-management-events"
GROUP = "eventing"
SERVICES = ["cloudtrail", "lambda"]

_EVENT_SOURCE = "lambda.amazonaws.com"
# CloudTrail records the URI-versioned name, and the suffix differs per operation.
_CREATE_EVENT = "CreateFunction20150331"
_PERMISSION_EVENT = "AddPermission20150331v2"
_GET_EVENT = "GetFunction20150331v2"

# CloudTrail documents delivery as about 5 minutes on average, not as a bound.
_INDEX_BUDGET_S = 420.0
_ROLE_PROPAGATION_BUDGET_S = 90.0
_ACTIVE_BUDGET_S = 90.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40


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
    # Registered BEFORE the create so LIFO runs it AFTER the delete.
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


def _function_name_of(record):
    return (record.get("requestParameters") or {}).get("functionName")


@tags(
    "axis:happy-path",
    "concern:eventing",
    "concern:negative-classes",
    "concern:representation",
    "cap:c2",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CreateFunction, AddPermission and a rejected GetFunction reach CloudTrail under their
    URI-versioned eventNames with the right error fields, while the function's zip and environment
    (which the API response still echoes) are stripped from the audit record.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    ct = ctx.client("cloudtrail")

    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    fn_name = ctx.unique_name("sim2real-xsvc-ctl-fn-")
    missing_name = ctx.unique_name("sim2real-xsvc-ctl-missing-")
    env_key = "SIMPARITY_AUDIT_" + uuid.uuid4().hex[:8].upper()
    env_value = "env-secret-" + uuid.uuid4().hex
    zip_marker = "zip-marker-" + uuid.uuid4().hex
    statement_id = "sim2real-" + uuid.uuid4().hex[:12]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            f"MARKER = {zip_marker!r}\n\n\ndef lambda_handler(event, context):\n    return MARKER\n",
        )
    zip_bytes = buf.getvalue()

    role_arn = _create_role(ctx, iam)
    created = _create_function(
        ctx,
        lam,
        logs,
        fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": zip_bytes},
        Environment={"Variables": {env_key: env_value}},
        Description=f"sim2real {CHECK}",
        Tags={"sim2real": CHECK},
    )
    # Positive control for the redaction legs: the caller DOES get the variable back.
    echoed = (created.get("Environment") or {}).get("Variables") or {}
    assert echoed == {env_key: env_value}, (
        f"CreateFunction must echo the environment to the caller: expected {{{env_key!r}: <value>}}, "
        f"actual {echoed!r}"
    )

    lam.add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceAccount=account_id,
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: lam.remove_permission(FunctionName=fn_name, StatementId=statement_id)
        )
    )

    code, resp = _error_code(lambda: lam.get_function(FunctionName=missing_name))
    assert code == "ResourceNotFoundException", (
        f"GetFunction on a random nonexistent name: expected ResourceNotFoundException, actual {code!r}"
    )
    want_missing = f"Function not found: arn:aws:lambda:{ctx.region}:{account_id}:function:{missing_name}"
    got_missing = resp.get("Error", {}).get("Message")
    assert got_missing == want_missing, (
        f"GetFunction on a missing name message: expected {want_missing!r}, actual {got_missing!r}"
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"GetFunction on a missing name: expected HTTP 404, actual "
        f"{resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    by_resource: dict[str, tuple[dict, dict]] = {}
    get_hit = None
    seen_names: set[str] = set()
    deadline = time.monotonic() + _INDEX_BUDGET_S
    while True:
        for ev in _lookup_all(
            ct,
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": fn_name}],
            StartTime=start,
        ):
            rec = json.loads(ev["CloudTrailEvent"])
            seen_names.add(rec.get("eventName"))
            if _function_name_of(rec) == fn_name:
                by_resource.setdefault(rec.get("eventName"), (rec, ev))
        # The failed GetFunction has an empty Resources list, so only an EventSource lookup finds it.
        if get_hit is None:
            for ev in _lookup_all(
                ct,
                LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": _EVENT_SOURCE}],
                StartTime=start,
            ):
                rec = json.loads(ev["CloudTrailEvent"])
                if _function_name_of(rec) == missing_name:
                    seen_names.add(rec.get("eventName"))
                    get_hit = (rec, ev)
                    break
        if _CREATE_EVENT in by_resource and _PERMISSION_EVENT in by_resource and get_hit:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"within {_INDEX_BUDGET_S:.0f}s CloudTrail must index {_CREATE_EVENT!r} and "
                f"{_PERMISSION_EVENT!r} for {fn_name!r} and a record for the failed GetFunction on "
                f"{missing_name!r}: actual eventNames for this resource {sorted(by_resource)!r}, "
                f"failed GetFunction found={get_hit is not None}, all eventNames seen "
                f"{sorted(n for n in seen_names if n)!r}"
            )
        time.sleep(_POLL_INTERVAL_S)

    create_rec, create_ev = by_resource[_CREATE_EVENT]
    perm_rec, _ = by_resource[_PERMISSION_EVENT]
    get_rec, get_ev = get_hit

    for label, rec in (("create", create_rec), ("permission", perm_rec), ("get", get_rec)):
        assert rec.get("eventSource") == _EVENT_SOURCE, (
            f"[{label}] eventSource: expected {_EVENT_SOURCE!r}, actual {rec.get('eventSource')!r}"
        )
        assert rec.get("eventCategory") == "Management", (
            f"[{label}] eventCategory: expected 'Management', actual {rec.get('eventCategory')!r}"
        )
        assert rec.get("awsRegion") == ctx.region, (
            f"[{label}] awsRegion: expected {ctx.region!r}, actual {rec.get('awsRegion')!r}"
        )
        assert rec.get("recipientAccountId") == account_id, (
            f"[{label}] recipientAccountId: expected {account_id!r}, actual "
            f"{rec.get('recipientAccountId')!r}"
        )

    assert create_ev.get("EventSource") == _EVENT_SOURCE, (
        f"LookupEvents summary EventSource: expected {_EVENT_SOURCE!r}, actual "
        f"{create_ev.get('EventSource')!r}"
    )
    assert {"ResourceType": "AWS::Lambda::Function", "ResourceName": fn_name} in (
        create_ev.get("Resources") or []
    ), (
        "the CreateFunction summary must name the function as an AWS::Lambda::Function resource: "
        f"actual {create_ev.get('Resources')!r}"
    )
    assert create_rec.get("errorCode") is None and create_rec.get("readOnly") is False, (
        "CreateFunction succeeded and writes: expected errorCode None and readOnly False, actual "
        f"{create_rec.get('errorCode')!r} / {create_rec.get('readOnly')!r}"
    )
    assert (create_rec.get("responseElements") or {}).get("functionArn") == created["FunctionArn"], (
        f"responseElements.functionArn: expected {created['FunctionArn']!r}, actual "
        f"{(create_rec.get('responseElements') or {}).get('functionArn')!r}"
    )
    assert (create_rec.get("responseElements") or {}).get("codeSha256") == created["CodeSha256"], (
        "responseElements.codeSha256 must be the digest of the package actually deployed: expected "
        f"{created['CodeSha256']!r}, actual {(create_rec.get('responseElements') or {}).get('codeSha256')!r}"
    )
    # Redaction: the package and the environment must not be in the audit record anywhere.
    blob = json.dumps(create_rec)
    assert env_value not in blob, (
        "the environment variable VALUE leaked into the CloudTrail record: expected absent, actual "
        f"present in {blob[:400]!r}"
    )
    assert env_key not in blob, (
        "the environment variable KEY leaked into the CloudTrail record: expected absent (real AWS "
        f"records 'environment': {{}}), actual present in {blob[:400]!r}"
    )
    assert zip_marker not in blob and base64.b64encode(zip_bytes).decode() not in blob, (
        "the deployment package leaked into the CloudTrail record: expected neither the zip bytes nor "
        "their contents present, actual present"
    )
    request_code = (create_rec.get("requestParameters") or {}).get("code")
    assert request_code == {}, (
        "requestParameters.code must be recorded with the ZipFile stripped: expected {}, actual "
        f"{request_code!r}"
    )

    perm_params = perm_rec.get("requestParameters") or {}
    assert perm_params.get("statementId") == statement_id, (
        f"AddPermission requestParameters.statementId: expected {statement_id!r}, actual "
        f"{perm_params.get('statementId')!r}"
    )
    assert perm_params.get("principal") == "s3.amazonaws.com", (
        f"AddPermission requestParameters.principal: expected 's3.amazonaws.com', actual "
        f"{perm_params.get('principal')!r}"
    )
    assert perm_rec.get("errorCode") is None and perm_rec.get("readOnly") is False, (
        "AddPermission succeeded and writes: expected errorCode None and readOnly False, actual "
        f"{perm_rec.get('errorCode')!r} / {perm_rec.get('readOnly')!r}"
    )
    assert perm_rec.get("eventID") != create_rec.get("eventID"), (
        f"two calls must be two records: both carry eventID {perm_rec.get('eventID')!r}"
    )

    assert get_rec.get("eventName") == _GET_EVENT, (
        f"failed GetFunction eventName: expected {_GET_EVENT!r}, actual {get_rec.get('eventName')!r}"
    )
    assert get_rec.get("errorCode") == "ResourceNotFoundException", (
        f"failed GetFunction errorCode: expected 'ResourceNotFoundException', actual "
        f"{get_rec.get('errorCode')!r}"
    )
    message = get_rec.get("errorMessage")
    assert message == want_missing, (
        f"failed GetFunction errorMessage must be the message the caller received: expected "
        f"{want_missing!r}, actual {message!r}"
    )
    assert get_rec.get("readOnly") is True, (
        f"GetFunction is a read: expected readOnly True, actual {get_rec.get('readOnly')!r}"
    )
    assert get_rec.get("responseElements") is None, (
        f"a rejected call has no response elements: expected None, actual {get_rec.get('responseElements')!r}"
    )
    assert get_ev.get("EventName") == _GET_EVENT, (
        f"LookupEvents summary EventName: expected {_GET_EVENT!r}, actual {get_ev.get('EventName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
