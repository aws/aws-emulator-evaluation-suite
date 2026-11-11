"""a-manual-approval-decision-is-audited-with-the-reviewer-role-not-the-pipeline."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-manual-approval-decision-is-audited-with-the-reviewer-role-not-the-pipeline"
GROUP = "eventing"
SERVICES = ["cloudtrail", "codepipeline"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_EVENT_SOURCE = "codepipeline.amazonaws.com"  # cloudTrailEventSource in the Smithy model
_APPROVAL_STAGE = "Review"
_APPROVAL_ACTION = "ManualApproval"

_PIPELINE_BUDGET_S = 420.0  # an execution starting and reaching the approval stage
_INDEX_BUDGET_S = 255.0  # ~1.9x the 80-136 s LookupEvents index latency for management events
_PROPAGATION_BUDGET_S = 120.0
# The artifact bucket accumulates execution artifacts, so draining it outlasts a short budget.
_CLEANUP_BUDGET_S = 240.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40


def _lookup_all(ct, **kw):
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
    raise AssertionError(
        f"{DATAPLANE_MARKER}: LookupEvents paged past {_PAGE_CEILING} pages without exhausting"
    )


def _put_approval_records(ct):
    return [
        json.loads(e["CloudTrailEvent"])
        for e in _lookup_all(
            ct,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "PutApprovalResult"}
            ],
        )
    ]


def _await(ct, predicate, why, budget_s=_INDEX_BUDGET_S):
    deadline = time.monotonic() + budget_s
    examined = 0
    while True:
        found = _put_approval_records(ct)
        examined = len(found)
        for rec in found:
            if predicate(rec):
                return rec
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no PutApprovalResult record satisfying {why} within "
                f"{budget_s:.0f}s; expected 1, actual 0 of {examined} examined"
            )
        time.sleep(_POLL_INTERVAL_S)


def _create_bucket(ctx, prefix, versioned=False):
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioned:
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _drain_and_delete_bucket(s3, bucket):
    """Empties object versions AND delete markers, then deletes. RAISES on a deadline miss."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        to_delete = []
        token = {}
        while True:
            page = s3.list_object_versions(Bucket=bucket, **token)
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            if not page.get("IsTruncated"):
                break
            token = {
                "KeyMarker": page["NextKeyMarker"],
                "VersionIdMarker": page.get("NextVersionIdMarker", ""),
            }
        for i in range(0, len(to_delete), 1000):
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete[i : i + 1000]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"bucket {bucket} still not empty after {_CLEANUP_BUDGET_S:.0f}s; LEAKING -- report "
                "the bucket name"
            )
        time.sleep(10.0)


def _create_pipeline_with_retry(cp, declaration, tags, *, timeout_s=_PROPAGATION_BUDGET_S):
    """CreatePipeline validates that it can assume the service role, so it answers
    InvalidStructureException while the freshly created role is still propagating. IAM exposes no
    condition to poll for, so the bounded retry IS the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration, tags=tags)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _delete_role_completely(iam, role_name):
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, iam, name, trust, inline):
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role_completely(iam, name))
    iam.put_role_policy(
        RoleName=name, PolicyName="simparity-inline", PolicyDocument=json.dumps(inline)
    )
    return iam.get_role(RoleName=name)["Role"]["Arn"]


def _assume_with_retry(sts, role_arn, session_name):
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    caller_arn = sts.get_caller_identity()["Arn"]
    not_yet = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    last = None
    while True:
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=3600
            )
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if last != "AccessDenied" or message != not_yet or time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssumeRole on {role_arn} did not become usable within "
                    f"{_PROPAGATION_BUDGET_S:.0f}s: expected success, actual code {last!r} ({message!r})"
                ) from exc
            time.sleep(5.0)


def _creds(resp):
    c = resp["Credentials"]
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _source_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("marker.txt", CHECK)
    return buf.getvalue()


def _refusal_code(fn):
    """Raises on unexpected success -- never returns a falsy sentinel."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        "re-submitting a spent approval token SUCCEEDED where a refusal was required; an "
        "over-permissive target must not reach the audit assertions below"
    )


def _await_approval_token(cp, pipeline_name, budget_s=_PIPELINE_BUDGET_S):
    """The live approval token, from GetPipelineState. Bounded; raises with the state it saw."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        state = cp.get_pipeline_state(name=pipeline_name)
        for stage in state.get("stageStates", []):
            if stage.get("stageName") != _APPROVAL_STAGE:
                continue
            for action in stage.get("actionStates", []):
                if action.get("actionName") != _APPROVAL_ACTION:
                    continue
                latest = action.get("latestExecution") or {}
                last = latest.get("status")
                token = latest.get("token")
                if last == "InProgress" and token:
                    return token, state.get("stageStates", [])
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the approval action {_APPROVAL_STAGE}/{_APPROVAL_ACTION} did not reach InProgress "
                f"with a token within {budget_s:.0f}s: expected 'InProgress' + a token, actual "
                f"status {last!r}"
            )
        time.sleep(_POLL_INTERVAL_S)


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CloudTrail attributes a PutApprovalResult decision to the reviewer's assumed role, not the
    pipeline service role, and audits the refused re-use of the spent token with its errorCode.

    Reference: https://docs.aws.amazon.com/codepipeline/latest/userguide/monitoring-cloudtrail-logs.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cp = ctx.client("codepipeline")
    ct = ctx.client("cloudtrail")

    source_bucket = _create_bucket(ctx, "simparity-ct-cpsrc-", versioned=True)
    artifact_bucket = _create_bucket(ctx, "simparity-ct-cpart-", versioned=True)
    source_key = "source.zip"
    s3.put_object(Bucket=source_bucket, Key=source_key, Body=_source_zip())

    service_role = ctx.unique_name("simparity-ct-cpsvc-")
    service_role_arn = _create_role(
        ctx,
        iam,
        service_role,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:GetBucketVersioning",
                        "s3:PutObject",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{source_bucket}",
                        f"arn:aws:s3:::{source_bucket}/*",
                        f"arn:aws:s3:::{artifact_bucket}",
                        f"arn:aws:s3:::{artifact_bucket}/*",
                    ],
                }
            ],
        },
    )

    # The reviewer. A DISTINCT role, so "attributed to the reviewer" is falsifiable against
    # "attributed to the pipeline service role" and against "attributed to the base principal".
    reviewer_role = ctx.unique_name("simparity-ct-reviewer-")
    reviewer_role_arn = _create_role(
        ctx,
        iam,
        reviewer_role,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["codepipeline:PutApprovalResult", "codepipeline:GetPipelineState"],
                    "Resource": "*",
                }
            ],
        },
    )
    assert reviewer_role_arn != service_role_arn, (
        "the reviewer and the pipeline service role must be different principals for the "
        f"attribution leg to be falsifiable: actual both {reviewer_role_arn!r}"
    )

    pipeline_name = ctx.unique_name("simparity-ct-pipe-")
    _create_pipeline_with_retry(
        cp,
        {
            "name": pipeline_name,
            "roleArn": service_role_arn,
            "artifactStore": {"type": "S3", "location": artifact_bucket},
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "S3Source",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "configuration": {
                                "S3Bucket": source_bucket,
                                "S3ObjectKey": source_key,
                                "PollForSourceChanges": "false",
                            },
                            "outputArtifacts": [{"name": "SourceOut"}],
                        }
                    ],
                },
                {
                    "name": _APPROVAL_STAGE,
                    "actions": [
                        {
                            "name": _APPROVAL_ACTION,
                            "actionTypeId": {
                                "category": "Approval",
                                "owner": "AWS",
                                "provider": "Manual",
                                "version": "1",
                            },
                            "configuration": {},
                        }
                    ],
                },
            ],
        },
        [{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_pipeline_quietly(cp, pipeline_name))

    token, _states = _await_approval_token(cp, pipeline_name)

    # ---- the decision, made as the reviewer -------------------------------------------------------
    reviewer = _assume_with_retry(sts, reviewer_role_arn, ctx.unique_name("reviewer")[:60])
    reviewer_session_arn = reviewer["AssumedRoleUser"]["Arn"]
    reviewer_cp = ctx.client("codepipeline", creds=_creds(reviewer))
    summary = f"approved-by-{CHECK}"
    reviewer_cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName=_APPROVAL_STAGE,
        actionName=_APPROVAL_ACTION,
        result={"summary": summary, "status": "Approved"},
        token=token,
    )

    # The spent token is refused; the code is captured at runtime, not guessed.
    sdk_code = _refusal_code(
        lambda: reviewer_cp.put_approval_result(
            pipelineName=pipeline_name,
            stageName=_APPROVAL_STAGE,
            actionName=_APPROVAL_ACTION,
            result={"summary": summary + "-replay", "status": "Approved"},
            token=token,
        )
    )
    assert sdk_code, f"the replay must carry an error code: actual {sdk_code!r}"

    # ---- CodePipeline's own view: a second, independent observable of the same decision ------------
    consumed = None
    deadline = time.monotonic() + _PIPELINE_BUDGET_S
    while True:
        state = cp.get_pipeline_state(name=pipeline_name)
        for stage in state.get("stageStates", []):
            if stage.get("stageName") != _APPROVAL_STAGE:
                continue
            for action in stage.get("actionStates", []):
                if action.get("actionName") == _APPROVAL_ACTION:
                    consumed = (action.get("latestExecution") or {}).get("status")
        if consumed == "Succeeded":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the approval action must reach Succeeded once approved: expected 'Succeeded', "
                f"actual {consumed!r} within {_PIPELINE_BUDGET_S:.0f}s"
            )
        time.sleep(_POLL_INTERVAL_S)

    # ---- terminal read at CloudTrail, via an operation CodePipeline was never asked for ---------
    approved = _await(
        ct,
        lambda r: pipeline_name in json.dumps(r.get("requestParameters") or {})
        and r.get("errorCode") is None,
        f"a successful PutApprovalResult naming pipeline {pipeline_name}",
    )
    assert approved.get("eventSource") == _EVENT_SOURCE, (
        f"eventSource: expected {_EVENT_SOURCE!r}, actual {approved.get('eventSource')!r}"
    )
    assert approved.get("eventCategory") == "Management", (
        f"eventCategory: expected 'Management', actual {approved.get('eventCategory')!r}"
    )
    assert approved.get("readOnly") is False, (
        f"PutApprovalResult writes, so readOnly must be False: actual {approved.get('readOnly')!r}"
    )

    ident = approved.get("userIdentity") or {}
    assert ident.get("type") == "AssumedRole", (
        f"the decision must be attributed to the session that made it: expected userIdentity.type "
        f"'AssumedRole', actual {ident.get('type')!r}"
    )
    issuer = (ident.get("sessionContext") or {}).get("sessionIssuer") or {}
    assert issuer.get("arn") == reviewer_role_arn, (
        "sessionContext.sessionIssuer.arn must be the REVIEWER's role, not the pipeline's service "
        f"role: expected {reviewer_role_arn!r}, actual {issuer.get('arn')!r} (H2 -- a target that "
        f"attributes the approval to the pipeline reports {service_role_arn!r} here)"
    )
    assert ident.get("arn") == reviewer_session_arn, (
        "userIdentity.arn must be the reviewer's SESSION arn, which is a different string from the "
        f"role arn: expected {reviewer_session_arn!r}, actual {ident.get('arn')!r}"
    )
    assert service_role_arn not in json.dumps(ident), (
        "the pipeline's service role must not appear in the approval's userIdentity at all: "
        f"expected {service_role_arn!r} absent, actual present in {json.dumps(ident)[:200]!r}"
    )

    req = approved.get("requestParameters") or {}
    serialised = json.dumps(req)
    assert req.get("pipelineName") == pipeline_name, (
        f"requestParameters.pipelineName: expected {pipeline_name!r}, actual "
        f"{req.get('pipelineName')!r} (H3 -- if the casing differs, correct the key)"
    )
    assert req.get("stageName") == _APPROVAL_STAGE, (
        f"requestParameters.stageName: expected {_APPROVAL_STAGE!r}, actual {req.get('stageName')!r}"
    )
    assert req.get("actionName") == _APPROVAL_ACTION, (
        f"requestParameters.actionName: expected {_APPROVAL_ACTION!r}, actual "
        f"{req.get('actionName')!r}"
    )
    assert (req.get("result") or {}).get("status") == "Approved", (
        "the DECISION itself must be in the record -- an audit trail that records that an approval "
        f"happened but not which way it went is useless: expected 'Approved', actual "
        f"{(req.get('result') or {}).get('status')!r}"
    )
    # Whether the approval token is recorded is undocumented, so the message reports it rather than
    # asserting it either way.
    assert summary in serialised, (
        f"the reviewer's summary must be recorded: expected {summary!r} inside "
        f"{serialised[:200]!r}, actual absent. "
        f"[H4 OBSERVATION for the blessing pass -- token present in record: "
        f"{token in serialised}; requestParameters.token == "
        f"{(req.get('token') or 'ABSENT')[:12]!r}...]"
    )

    # The refusal must be audited too -- this is how "correctly refused" is told from "never sent".
    refused = _await(
        ct,
        lambda r: pipeline_name in json.dumps(r.get("requestParameters") or {})
        and r.get("errorCode") is not None,
        f"a REFUSED PutApprovalResult naming pipeline {pipeline_name}",
    )
    # For PutApprovalResult, CloudTrail's errorCode is the SDK's error code VERBATIM -- unlike
    # AccessDeniedException -> AccessDenied elsewhere, the trailing "Exception" is NOT stripped.
    expected_audit_code = sdk_code
    assert refused.get("errorCode") == expected_audit_code, (
        "the audited errorCode must equal the SDK error code verbatim for PutApprovalResult (H6, "
        f"measured -- not every operation strips a trailing 'Exception'): expected "
        f"{expected_audit_code!r} (SDK code {sdk_code!r}), actual {refused.get('errorCode')!r}"
    )
    assert refused.get("errorMessage"), (
        f"a refused call must record an errorMessage: actual {refused.get('errorMessage')!r}"
    )
    assert not refused.get("responseElements"), (
        "a REFUSED call must record no responseElements: expected empty/None, actual "
        f"{refused.get('responseElements')!r}"
    )
    assert refused.get("eventID") != approved.get("eventID"), (
        "the approval and its refused replay must be two distinct records: expected different "
        f"eventIDs, actual both {approved.get('eventID')!r}"
    )
    # The refusal is attributed to the same reviewer -- a target that drops identity on the error
    # path fails here.
    refused_issuer = (
        (refused.get("userIdentity") or {}).get("sessionContext") or {}
    ).get("sessionIssuer") or {}
    assert refused_issuer.get("arn") == reviewer_role_arn, (
        "a refused call must still be attributed to its caller: expected "
        f"{reviewer_role_arn!r}, actual {refused_issuer.get('arn')!r}"
    )


def _delete_pipeline_quietly(cp, name):
    try:
        cp.delete_pipeline(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "PipelineNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
