"""obs-sfn-2-data-selector-logs-start-sync-execution-to-the-trail-prefix-only-after-it-is-added."""
from __future__ import annotations

import datetime
import gzip
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-2-data-selector-logs-start-sync-execution-to-the-trail-prefix-only-after-it-is-added"
GROUP = "eventing"
SERVICES = ["cloudtrail", "stepfunctions"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# CloudTrail batches log files to S3 roughly every five minutes, a freshly started trail is not
# capturing for some time after StartLogging returns, and an event-selector change is eventually
# consistent. Each phase therefore waits on a delivered record, and all phases share one deadline.
_TOTAL_BUDGET_S = 1500.0
_CALL_INTERVAL_S = 15.0
_POLL_INTERVAL_S = 2.0
_CLEANUP_BUDGET_S = 240.0
_IAM_RETRY_DEADLINE_S = 90.0

_RESOURCE_TYPE = "AWS::StepFunctions::StateMachine"
_DEFINITION = {
    "Comment": "sim2real cloudtrail__sfn data-event subject",
    "StartAt": "Echo",
    "States": {"Echo": {"Type": "Pass", "End": True}},
}
_MGMT_SELECTOR = {
    "Name": "management",
    "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}],
}


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An advanced Data selector on a StateMachine ARN delivers that EXPRESS machine's
    StartSyncExecution data event to the trail's S3 prefix, only for calls made after the selector
    was added and never for a bystander machine.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")

    prefix = ctx.unique_name("sim2real-ctsfn-")
    bucket = _create_log_bucket(ctx, s3, account, prefix)

    exec_role_arn = _create_execution_role(ctx, iam)
    subject_arn = _create_state_machine(ctx, sfn, exec_role_arn)
    bystander_arn = _create_state_machine(ctx, sfn, exec_role_arn)

    trail_name = ctx.unique_name("sim2real-xsvc-ctsfn-")
    trail_arn = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        S3KeyPrefix=prefix,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_arn))
    ct.put_event_selectors(TrailName=trail_arn, AdvancedEventSelectors=[_MGMT_SELECTOR])
    ct.start_logging(Name=trail_arn)
    ctx.on_cleanup(lambda: _stop_logging_quietly(ct, trail_arn))
    status = ct.get_trail_status(Name=trail_arn)
    assert status.get("IsLogging") is True, (
        f"the trail must be logging before the BEFORE call: expected IsLogging True, actual "
        f"{status.get('IsLogging')!r}"
    )

    budget_s = _budget_s(ctx, _TOTAL_BUDGET_S)
    deadline = time.monotonic() + budget_s
    files: dict[str, list[dict]] = {}

    def _marker():
        """A management event whose delivery proves the trail was capturing at that instant."""
        return sfn.describe_state_machine(stateMachineArn=subject_arn)["ResponseMetadata"][
            "RequestId"]

    def _delivered_ids():
        _collect(s3, bucket, prefix, files)
        return {r.get("requestID") for rs in files.values() for r in rs}

    # ---- phase 0: the trail is demonstrably capturing ---------------------------------------
    live_markers = [_marker()]
    last_fire = time.monotonic()
    while not set(live_markers) & _delivered_ids():
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"the trail's first management event in s3://{bucket}/{prefix}/: the run "
                    f"budget ended first; not graded"
                )
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the trail never delivered any of {len(live_markers)} "
                f"DescribeStateMachine management events to s3://{bucket}/{prefix}/ within "
                f"{budget_s:.0f}s of StartLogging; delivered "
                f"{sorted({r.get('eventName') for rs in files.values() for r in rs})!r}"
            )
        if time.monotonic() - last_fire >= _CALL_INTERVAL_S:
            live_markers.append(_marker())
            last_fire = time.monotonic()
        time.sleep(_POLL_INTERVAL_S)

    # ---- phase 1: the BEFORE call, bracketed by a management marker after it ------------------
    before_name = ctx.unique_name("sim2real-before-")
    before = sfn.start_sync_execution(
        stateMachineArn=subject_arn, name=before_name, input=json.dumps({"leg": before_name}))
    assert before["status"] == "SUCCEEDED" and json.loads(before["output"]) == {"leg": before_name}, (
        f"the BEFORE StartSyncExecution must run the machine: expected SUCCEEDED echoing "
        f"{{'leg': {before_name!r}}}, actual {before.get('status')!r} {before.get('output')!r}"
    )
    before_exec_arn = before["executionArn"]
    marker_request_id = _marker()

    # ---- leg 2: add the data selector -------------------------------------------------------
    data_selector = {
        "Name": "sfn-subject-data",
        "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": [_RESOURCE_TYPE]},
            {"Field": "resources.ARN", "Equals": [subject_arn]},
        ],
    }
    ct.put_event_selectors(TrailName=trail_arn,
                           AdvancedEventSelectors=[_MGMT_SELECTOR, data_selector])
    stored = ct.get_event_selectors(TrailName=trail_arn).get("AdvancedEventSelectors") or []
    stored_data = [s for s in stored if s.get("Name") == "sfn-subject-data"]
    assert len(stored_data) == 1 and {
        f["Field"]: f.get("Equals") for f in stored_data[0]["FieldSelectors"]
    } == {"eventCategory": ["Data"], "resources.type": [_RESOURCE_TYPE],
          "resources.ARN": [subject_arn]}, (
        f"GetEventSelectors must return the data selector as put: actual {stored!r}"
    )

    after_execs: dict[str, str] = {}      # execution name -> SDK request id, subject
    bystander_execs: dict[str, str] = {}  # execution name -> SDK request id, bystander

    def _fire():
        for target, sink, label in ((subject_arn, after_execs, "after"),
                                    (bystander_arn, bystander_execs, "bystander")):
            name = ctx.unique_name(f"sim2real-{label}-")
            out = sfn.start_sync_execution(
                stateMachineArn=target, name=name, input=json.dumps({"leg": name}))
            assert out["status"] == "SUCCEEDED", (
                f"[{label}] StartSyncExecution must succeed: actual {out.get('status')!r} "
                f"{out.get('error')!r} {out.get('cause')!r}"
            )
            assert out["executionArn"].split(":")[-2] == name, (
                f"[{label}] the execution ARN must carry the name given: {out['executionArn']!r}"
            )
            sink[name] = out["ResponseMetadata"]["RequestId"]

    selector_at = time.monotonic()
    last_fire = time.monotonic()
    _fire()
    found_after = None
    while found_after is None:
        _collect(s3, bucket, prefix, files)
        for key, records in files.items():
            for rec in records:
                if (rec.get("eventName") == "StartSyncExecution"
                        and (rec.get("requestParameters") or {}).get("name") in after_execs):
                    found_after = (key, rec)
                    break
            if found_after:
                break
        if found_after:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"a StartSyncExecution data event in s3://{bucket}/{prefix}/: the run budget "
                    f"ended first; not graded"
                )
            st = ct.get_trail_status(Name=trail_arn)
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no StartSyncExecution data event for the subject machine "
                f"reached s3://{bucket}/{prefix}/ within {time.monotonic() - selector_at:.0f}s of adding the "
                f"{_RESOURCE_TYPE} selector; {len(after_execs)} subject call(s) made, "
                f"{len(files)} log file(s) delivered holding "
                f"{sorted({r.get('eventName') for rs in files.values() for r in rs})!r}; sample "
                f"StartSyncExecution records: "
                f"{json.dumps([r for rs in files.values() for r in rs if r.get('eventName') == 'StartSyncExecution'][:2], default=str)[:2500]}. trail: "
                f"IsLogging={st.get('IsLogging')!r} LatestDeliveryTime="
                f"{st.get('LatestDeliveryTime')!r} LatestDeliveryError="
                f"{st.get('LatestDeliveryError')!r}"
            )
        if time.monotonic() - last_fire >= _CALL_INTERVAL_S:
            _fire()
            last_fire = time.monotonic()
        time.sleep(_POLL_INTERVAL_S)
    found_at = datetime.datetime.now(datetime.timezone.utc)

    key, rec = found_after
    exec_name = rec["requestParameters"]["name"]
    assert rec.get("eventCategory") == "Data", (
        f"StartSyncExecution under a {_RESOURCE_TYPE} selector is a data event: expected "
        f"eventCategory 'Data', actual {rec.get('eventCategory')!r} ({json.dumps(rec)[:600]})"
    )
    assert rec.get("managementEvent") is False, (
        f"expected managementEvent False on a data event, actual {rec.get('managementEvent')!r}"
    )
    assert rec.get("eventSource") == "states.amazonaws.com", (
        f"expected eventSource 'states.amazonaws.com', actual {rec.get('eventSource')!r}"
    )
    assert (rec.get("requestParameters") or {}).get("stateMachineArn") == subject_arn, (
        f"data event requestParameters.stateMachineArn: expected {subject_arn!r}, actual "
        f"{(rec.get('requestParameters') or {}).get('stateMachineArn')!r}"
    )
    assert rec.get("requestID") == after_execs[exec_name], (
        f"data event requestID {rec.get('requestID')!r} is not the request id the SDK observed on "
        f"that StartSyncExecution ({after_execs[exec_name]!r})"
    )
    # A StartSyncExecution data event records no responseElements and redacts the execution input
    # with this literal sentinel rather than omitting the member.
    assert rec.get("responseElements") is None, (
        f"data event responseElements: expected None, actual {rec.get('responseElements')!r}"
    )
    assert (rec.get("requestParameters") or {}).get("input") == "HIDDEN_DUE_TO_SECURITY_REASONS", (
        f"the execution input must be redacted, not logged: expected "
        f"'HIDDEN_DUE_TO_SECURITY_REASONS', actual "
        f"{(rec.get('requestParameters') or {}).get('input')!r}"
    )
    assert rec.get("readOnly") is False, (
        f"StartSyncExecution is a write: expected readOnly False, actual {rec.get('readOnly')!r}"
    )
    assert any(r.get("ARN") == subject_arn and r.get("type") == _RESOURCE_TYPE
               for r in rec.get("resources") or []), (
        f"data event resources must name the subject as {_RESOURCE_TYPE}: actual "
        f"{rec.get('resources')!r}"
    )
    assert rec.get("recipientAccountId") == account and rec.get("awsRegion") == ctx.region, (
        f"data event account/region: expected {account!r}/{ctx.region!r}, actual "
        f"{rec.get('recipientAccountId')!r}/{rec.get('awsRegion')!r}"
    )
    layout = re.compile(
        rf"^{re.escape(prefix)}/AWSLogs/{account}/CloudTrail/{re.escape(ctx.region)}/"
        rf"\d{{4}}/\d{{2}}/\d{{2}}/{account}_CloudTrail_{re.escape(ctx.region)}_[0-9TZ]+_\w+\.json\.gz$"
    )
    assert layout.match(key), (
        f"the data event's log file must sit at the documented key layout under the trail "
        f"prefix {prefix!r}: actual key {key!r}"
    )

    # ---- flush barrier: a marker made after every graded call is delivered -----------------
    barrier_request_id = _marker()
    while True:
        delivered = _delivered_ids()
        if barrier_request_id in delivered and marker_request_id in delivered:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"the trail to deliver the barrier marker {barrier_request_id!r}: the run "
                    f"budget ended first; not graded"
                )
            st = ct.get_trail_status(Name=trail_arn)
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the trail did not deliver the barrier marker "
                f"{barrier_request_id!r} and the post-BEFORE marker within the {budget_s:.0f}s "
                f"budget after {found_at.isoformat()} (LatestDeliveryTime "
                f"{st.get('LatestDeliveryTime')!r}), so the absence legs cannot be barriered"
            )
        time.sleep(_POLL_INTERVAL_S)
    _collect(s3, bucket, prefix, files)
    all_records = [r for rs in files.values() for r in rs]

    # Positive control for the BEFORE leg: the management call made right after it is delivered.
    marker_recs = [r for r in all_records if r.get("eventName") == "DescribeStateMachine"
                   and r.get("requestID") == marker_request_id]
    assert len(marker_recs) == 1, (
        f"the management marker beside the BEFORE call (DescribeStateMachine, request id "
        f"{marker_request_id!r}) must be delivered exactly once, proving the trail was logging "
        f"then: actual {len(marker_recs)} of {len(all_records)} records, eventNames "
        f"{sorted({(r.get('eventName'), r.get('eventCategory')) for r in all_records})!r}"
    )
    assert marker_recs[0].get("eventCategory") == "Management", (
        f"marker eventCategory: expected 'Management', actual "
        f"{marker_recs[0].get('eventCategory')!r}"
    )

    before_recs = [r for r in all_records if before_name in json.dumps(r)
                   or before_exec_arn in json.dumps(r)]
    assert before_recs == [], (
        f"a data selector is not retroactive: the StartSyncExecution made BEFORE it existed "
        f"({before_exec_arn!r}) must be absent from every delivered file, actual "
        f"{len(before_recs)} record(s): {json.dumps(before_recs)[:600]}"
    )
    stray = [r for r in all_records if r.get("eventName") == "StartSyncExecution"
             and (r.get("requestParameters") or {}).get("stateMachineArn") == bystander_arn]
    assert stray == [], (
        f"the selector's resources.ARN names only the subject: expected 0 StartSyncExecution "
        f"records for the bystander {bystander_arn!r} after {len(bystander_execs)} calls, actual "
        f"{len(stray)}"
    )
    delivered_after = [r for r in all_records if r.get("eventName") == "StartSyncExecution"
                       and (r.get("requestParameters") or {}).get("name") in after_execs]
    categories = sorted({r.get("eventCategory") for r in delivered_after})
    assert categories == ["Data"], (
        f"every delivered AFTER StartSyncExecution must be a Data event, none a Management "
        f"duplicate: expected ['Data'], actual {categories!r} over {len(delivered_after)} records"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _collect(s3, bucket, prefix, files):
    """Download and parse every log file under the prefix not already read."""
    token = None
    while True:
        kw = {"Bucket": bucket, "Prefix": f"{prefix}/AWSLogs/"}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        for obj in page.get("Contents", []):
            k = obj["Key"]
            if k in files or not k.endswith(".json.gz") or "/CloudTrail/" not in k:
                continue
            body = s3.get_object(Bucket=bucket, Key=k)["Body"].read()
            files[k] = json.loads(gzip.decompress(body)).get("Records", [])
        token = page.get("NextContinuationToken")
        if not token:
            return


def _create_log_bucket(ctx, s3, account, prefix):
    name = ctx.unique_name("sim2real-xsvc-ctsfn-")
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default; a LocationConstraint naming it is a 400.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{name}"},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject",
             "Resource": f"arn:aws:s3:::{name}/{prefix}/AWSLogs/{account}/*",
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ],
    }))
    return name


def _drain_and_delete_bucket(s3, bucket):
    """Empty and delete the bucket; CloudTrail can still write for a while after StopLogging."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        token = None
        while True:
            kw = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            page = s3.list_objects_v2(**kw)
            keys = [o["Key"] for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket,
                                  Delete={"Objects": [{"Key": k} for k in keys]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            token = page.get("NextContinuationToken")
            if not token:
                break
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
            raise AssertionError(f"bucket {bucket} still not empty after "
                                 f"{_CLEANUP_BUDGET_S:.0f}s")
        time.sleep(2.0)


def _stop_logging_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


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

    def _delete():
        for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pname)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete)
    return arn


def _create_state_machine(ctx, sfn, role_arn):
    """An EXPRESS machine; retries the AccessDeniedException a not-yet-assumable role produces."""
    name = ctx.unique_name("sim2real-xsvc-ctsfn-sm-")
    deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(_DEFINITION), roleArn=role_arn,
                type="EXPRESS", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
