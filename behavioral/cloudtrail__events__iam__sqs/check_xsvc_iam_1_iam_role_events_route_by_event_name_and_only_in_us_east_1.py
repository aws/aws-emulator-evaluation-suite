"""xsvc-iam-1-iam-role-events-route-by-event-name-and-only-in-us-east-1."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-1-iam-role-events-route-by-event-name-and-only-in-us-east-1"
GROUP = "eventing"
SERVICES = ["cloudtrail", "events", "iam", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# IAM is a global service: its CloudTrail events are recorded, and EventBridge delivers them, in
# us-east-1 only. That is the subject of the check; the comparison region comes from ctx.region.
_LEADER_REGION = "us-east-1"
_FALLBACK_COMPARISON_REGION = "us-west-2"

_DETAIL_TYPE = "AWS API Call via CloudTrail"
# Each delivered body names the rule that sent it and carries the original event verbatim.
_TEMPLATE = '{"rule": "<aws.events.rule-name>", "event": <aws.events.event.json>}'

_COLD_DELIVERY_BUDGET_S = 1000.0  # first leg may pay the trail->bus warm-up
_WARM_DELIVERY_BUDGET_S = 240.0  # legs after the channel is shown live
_ABSENCE_HOLD_S = 40.0  # extra draining after a barrier, before an absence is asserted
_TEARDOWN_BUDGET_S = 150.0  # in-body trail+bucket teardown (the cleanup chain is only 60 s)
_CLEANUP_BUCKET_BUDGET_S = 40.0  # the safety-net bucket drain inside the cleanup chain
_LONG_POLL_S = 10
# Writes made just after a trail starts can be lost rather than delayed, so they are re-issued.
_REEMIT_S = 120.0


def _error_code(exc):
    return exc.response.get("Error", {}).get("Code")


def _create_trail_bucket(ctx, s3, account_id):
    name = ctx.unique_name("sim2real-xsvc-iamct-")
    # us-east-1 is CreateBucket's own default; passing a LocationConstraint for it is a 400.
    s3.create_bucket(Bucket=name)
    ctx.on_cleanup(
        lambda: _drain_and_delete_bucket(s3, name, _CLEANUP_BUCKET_BUDGET_S, raise_on_leak=True)
    )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_policy(
        Bucket=name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{name}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{name}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )
    return name


def _drain_and_delete_bucket(s3, bucket, budget_s, *, raise_on_leak: bool = False):
    """Returns True once the bucket is gone. CloudTrail can land one more log file after the trail
    stops, so the empty-then-delete repeats until the deadline, then returns False for the
    registered cleanup to retry, or raises when ``raise_on_leak`` (that cleanup)."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            keys = []
            token = None
            while True:
                kw = {"Bucket": bucket, "MaxKeys": 1000}
                if token:
                    kw["ContinuationToken"] = token
                page = s3.list_objects_v2(**kw)
                keys.extend(o["Key"] for o in page.get("Contents", []))
                token = page.get("NextContinuationToken")
                if not token:
                    break
            for i in range(0, len(keys), 1000):
                s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
                )
            s3.delete_bucket(Bucket=bucket)
            return True
        except ClientError as exc:
            if _error_code(exc) == "NoSuchBucket":
                return True
            if _error_code(exc) != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            msg = f"s3 bucket {bucket} still not empty after {budget_s:.0f}s"
            if raise_on_leak:
                raise RuntimeError(msg)
            return False


def _delete_trail_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if _error_code(exc) != "TrailNotFoundException":
            raise
    try:
        ct.delete_trail(Name=trail_arn)
    except ClientError as exc:
        if _error_code(exc) != "TrailNotFoundException":
            raise


def _create_queue(ctx, sqs, label):
    name = ctx.unique_name(f"sim2real-xsvc-iam{label}-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quietly(sqs, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _delete_queue_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if "NonExistentQueue" not in str(_error_code(exc)):
            raise


def _allow_rules_to_send(sqs, queue_url, queue_arn, rule_arns):
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "EventBridgeRulesOnly",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arns}},
                        }
                    ],
                }
            )
        },
    )


def _put_rule_to_queue(ctx, events, pattern, queue_arn):
    name = ctx.unique_name("sim2real-xsvc-iamrule-")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    events.put_targets(
        Rule=name,
        Targets=[
            {
                "Id": "sink",
                "Arn": queue_arn,
                "InputTransformer": {"InputPathsMap": {}, "InputTemplate": _TEMPLATE},
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=name, Ids=["sink"], Force=True))
    return name, arn


def _collect(sqs, url, sink, wait_s):
    """Long-poll once for up to wait_s, then drain whatever else is visible. Every message is
    deleted as it is read, so none can resurface after its visibility timeout and be mistaken for
    a fresh delivery in a later absence assertion."""
    wait = wait_s
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait, VisibilityTimeout=60
        ).get("Messages", [])
        if not msgs:
            return
        for m in msgs:
            sink.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        wait = 0


def _detail(msg):
    return (msg.get("event") or {}).get("detail") or {}


def _iam_hits(msgs, event_name, role_name, rule=None):
    return [
        m
        for m in msgs
        if (rule is None or m.get("rule") == rule)
        and _detail(m).get("eventName") == event_name
        and (_detail(m).get("requestParameters") or {}).get("roleName") == role_name
    ]


def _tag_hits(msgs, marker):
    return [
        m
        for m in msgs
        if _detail(m).get("eventName") == "TagQueue"
        and marker in json.dumps(_detail(m).get("requestParameters") or {})
    ]


def _delete_role_quietly(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _error_code(exc) != "NoSuchEntity":
            raise


@tags("axis:negative-delivery", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """IAM role events reach only the rule naming their eventName, and only in us-east-1.
    A comparison-region rule matching the same IAM events gets its TagQueue events but no IAM ones.
    Delivered source, detail-type, eventName, roleName, region and account are asserted exact.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cmp_region = ctx.region if ctx.region != _LEADER_REGION else _FALLBACK_COMPARISON_REGION
    assert cmp_region != _LEADER_REGION, (
        f"the comparison region resolved to {cmp_region!r}, the same as the leader region"
    )

    iam = ctx.client("iam")
    s3 = ctx.client("s3", region=_LEADER_REGION)
    ct = ctx.client("cloudtrail", region=_LEADER_REGION)
    ev_lead = ctx.client("events", region=_LEADER_REGION)
    ev_cmp = ctx.client("events", region=cmp_region)
    sqs_lead = ctx.client("sqs", region=_LEADER_REGION)
    sqs_cmp = ctx.client("sqs", region=cmp_region)

    # ---- the trail ----------------------------------------------------------------------
    bucket = _create_trail_bucket(ctx, s3, account_id)
    trail_name = ctx.unique_name("sim2real-xsvc-iamct-")
    trail_arn = None
    attempts = 0
    while trail_arn is None:
        attempts += 1
        try:
            trail_arn = ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket,
                IsMultiRegionTrail=True,
                IncludeGlobalServiceEvents=True,
                TagsList=[{"Key": "sim2real", "Value": CHECK}],
            )["TrailARN"]
        except ClientError as exc:
            # The bucket policy is eventually consistent; this is the only code that means "not
            # yet", and it is retried rather than asserted.
            if _error_code(exc) != "InsufficientS3BucketPolicyException" or attempts >= 30:
                raise
    ctx.on_cleanup(lambda: _delete_trail_quietly(ct, trail_arn))
    ct.put_event_selectors(
        TrailName=trail_arn,
        EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
    )
    ct.start_logging(Name=trail_arn)
    selectors = ct.get_event_selectors(TrailName=trail_arn).get("EventSelectors") or []
    assert [(s.get("ReadWriteType"), s.get("IncludeManagementEvents")) for s in selectors] == [
        ("WriteOnly", True)
    ], f"the trail must log write management events only: actual selectors {selectors!r}"
    status = ct.get_trail_status(Name=trail_arn)
    assert status.get("IsLogging") is True, (
        f"the trail must be logging before any write is made (F1): actual {status!r}"
    )

    # ---- the us-east-1 queue and its two rules ------------------------------------------------
    q_url, q_arn = _create_queue(ctx, sqs_lead, "q")
    iam_base = {
        "source": ["aws.iam"],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"eventSource": ["iam.amazonaws.com"]},
    }
    pat_a = json.loads(json.dumps(iam_base))
    pat_a["detail"]["eventName"] = ["CreateRole"]
    pat_b = json.loads(json.dumps(iam_base))
    pat_b["detail"]["eventName"] = ["DeleteRole"]
    rule_a, rule_a_arn = _put_rule_to_queue(ctx, ev_lead, pat_a, q_arn)
    rule_b, rule_b_arn = _put_rule_to_queue(ctx, ev_lead, pat_b, q_arn)
    _allow_rules_to_send(sqs_lead, q_url, q_arn, [rule_a_arn, rule_b_arn])

    # ---- the comparison-region queue and rule ---------------------------------------------------
    c_url, c_arn = _create_queue(ctx, sqs_cmp, "cmp")
    pat_c = {
        "source": ["aws.iam", "aws.sqs"],
        "detail-type": [_DETAIL_TYPE],
        "detail": {
            "eventSource": ["iam.amazonaws.com", "sqs.amazonaws.com"],
            "eventName": ["CreateRole", "DeleteRole", "TagQueue"],
        },
    }
    rule_c, rule_c_arn = _put_rule_to_queue(ctx, ev_cmp, pat_c, c_arn)
    _allow_rules_to_send(sqs_cmp, c_url, c_arn, [rule_c_arn])

    # ---- leg 1: CreateRole (global) and TagQueue #1 (regional), back to back ----------------------
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    candidates = {}  # role name -> RoleId, in creation order; re-emitted until one is delivered

    def _new_candidate():
        name = ctx.unique_name("sim2real-xsvc-iamrole-")
        candidates[name] = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=trust,
            Description="sim2real-xsvc cloudtrail->eventbridge routing subject",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["RoleId"]
        ctx.on_cleanup(lambda: _delete_role_quietly(iam, name))

    def _subject():
        for name in candidates:
            if _iam_hits(at_q, "CreateRole", name, rule_a):
                return name
        return None

    at_q, at_c = [], []
    _new_candidate()
    markers1 = [ctx.unique_name("m1-")]
    sqs_cmp.tag_queue(QueueUrl=c_url, Tags={"sim2real-marker": markers1[-1]})
    started = time.monotonic()
    next_reemit = started + _REEMIT_S
    next_role_reemit = started + _REEMIT_S

    def _first_tag_hits():
        return [m for mk in markers1 for m in _tag_hits(at_c, mk)]

    deadline = started + _COLD_DELIVERY_BUDGET_S
    while True:
        _collect(sqs_lead, q_url, at_q, _LONG_POLL_S)
        _collect(sqs_cmp, c_url, at_c, _LONG_POLL_S)
        if _subject() and _first_tag_hits():
            break
        if not _subject() and time.monotonic() >= next_role_reemit:
            _new_candidate()
            next_role_reemit = time.monotonic() + _REEMIT_S
        if not _first_tag_hits() and time.monotonic() >= next_reemit:
            markers1.append(ctx.unique_name("m1-"))
            sqs_cmp.tag_queue(QueueUrl=c_url, Tags={"sim2real-marker": markers1[-1]})
            next_reemit = time.monotonic() + _REEMIT_S
        if time.monotonic() >= deadline:
            st = ct.get_trail_status(Name=trail_arn)
            raise AssertionError(
                f"{DATAPLANE_MARKER}: within {_COLD_DELIVERY_BUDGET_S:.0f}s expected rule A "
                f"({rule_a}) to deliver iam:CreateRole for any of {len(candidates)} candidate "
                f"roles {list(candidates)!r} in {_LEADER_REGION} AND "
                f"the {cmp_region} rule to deliver any of {len(markers1)} sqs:TagQueue markers "
                f"{markers1!r}; actual "
                f"{0 if _subject() is None else 1} subject CreateRole at A, "
                f"{len(_first_tag_hits())} TagQueue at the comparison rule "
                f"({len(at_q)} / {len(at_c)} messages seen in total). Trail: "
                f"IsLogging={st.get('IsLogging')!r} "
                f"LatestDeliveryError={st.get('LatestDeliveryError')!r} "
                f"LatestDeliveryTime={st.get('LatestDeliveryTime')!r}"
            )
    create_latency_s = time.monotonic() - started
    role_name = _subject()
    role_id = candidates[role_name]

    env = _iam_hits(at_q, "CreateRole", role_name, rule_a)[0]["event"]
    detail = env.get("detail") or {}
    assert env.get("source") == "aws.iam", (
        f"source: expected 'aws.iam', actual {env.get('source')!r}"
    )
    assert env.get("detail-type") == _DETAIL_TYPE, (
        f"detail-type: expected {_DETAIL_TYPE!r}, actual {env.get('detail-type')!r}"
    )
    assert detail.get("eventSource") == "iam.amazonaws.com", (
        f"detail.eventSource: expected 'iam.amazonaws.com', actual {detail.get('eventSource')!r}"
    )
    assert detail.get("eventName") == "CreateRole", (
        f"detail.eventName: expected 'CreateRole', actual {detail.get('eventName')!r}"
    )
    assert (detail.get("requestParameters") or {}).get("roleName") == role_name, (
        f"detail.requestParameters.roleName: expected {role_name!r}, actual "
        f"{(detail.get('requestParameters') or {}).get('roleName')!r}"
    )
    assert env.get("region") == _LEADER_REGION and detail.get("awsRegion") == _LEADER_REGION, (
        f"a global IAM event is placed in {_LEADER_REGION}: actual envelope region "
        f"{env.get('region')!r}, detail.awsRegion {detail.get('awsRegion')!r} (call signed in "
        f"{ctx.region!r})"
    )
    assert env.get("account") == account_id, (
        f"envelope account: expected {account_id!r}, actual {env.get('account')!r}"
    )
    assert detail.get("readOnly") is False, (
        f"CreateRole is a write, so detail.readOnly must be False: actual {detail.get('readOnly')!r}"
    )
    assert role_id in json.dumps(detail.get("responseElements") or {}), (
        f"detail.responseElements must carry the RoleId CreateRole returned in this run "
        f"({role_id!r}): actual {json.dumps(detail.get('responseElements'))[:300]!r}"
    )

    # The negative: B delivers nothing for the create. A's arrival on the SAME queue is the
    # barrier, and a further hold keeps draining before the absence is asserted.
    hold_until = time.monotonic() + _ABSENCE_HOLD_S
    while time.monotonic() < hold_until:
        _collect(sqs_lead, q_url, at_q, _LONG_POLL_S)
    b_overmatch = [
        m for m in at_q if m.get("rule") == rule_b and _detail(m).get("eventName") != "DeleteRole"
    ]
    b_on_role = [
        m for m in at_q if m.get("rule") == rule_b and _iam_hits([m], "CreateRole", role_name)
    ]
    assert b_overmatch == [] and b_on_role == [], (
        f"rule B ({rule_b}) matches eventName DeleteRole only and the role has not been deleted, "
        f"so it must deliver nothing for the create: actual {len(b_overmatch)} non-DeleteRole "
        f"deliveries and {len(b_on_role)} naming {role_name!r}, e.g. "
        f"{json.dumps((b_overmatch or b_on_role)[:1])[:300]!r}. Positive control: rule A on the "
        f"same queue delivered this CreateRole after {create_latency_s:.0f}s"
    )

    # ---- leg 2: DeleteRole must reach B, and only B ----------------------------------------------
    iam.delete_role(RoleName=role_name)
    deadline = time.monotonic() + _WARM_DELIVERY_BUDGET_S
    while not _iam_hits(at_q, "DeleteRole", role_name, rule_b):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: rule B ({rule_b}) never delivered iam:DeleteRole for "
                f"{role_name!r} within {_WARM_DELIVERY_BUDGET_S:.0f}s, although the channel "
                f"delivered the CreateRole to rule A on the same queue in {create_latency_s:.0f}s; "
                f"expected 1, actual 0 of {len(at_q)} messages seen"
            )
        _collect(sqs_lead, q_url, at_q, _LONG_POLL_S)
    del_env = _iam_hits(at_q, "DeleteRole", role_name, rule_b)[0]["event"]
    assert del_env.get("source") == "aws.iam" and del_env.get("detail-type") == _DETAIL_TYPE, (
        f"DeleteRole envelope: expected source 'aws.iam' and detail-type {_DETAIL_TYPE!r}, actual "
        f"{del_env.get('source')!r} / {del_env.get('detail-type')!r}"
    )
    assert del_env.get("region") == _LEADER_REGION, (
        f"DeleteRole envelope region: expected {_LEADER_REGION!r}, actual {del_env.get('region')!r}"
    )
    a_overmatch = [
        m for m in at_q if m.get("rule") == rule_a and _detail(m).get("eventName") != "CreateRole"
    ]
    assert a_overmatch == [], (
        f"rule A ({rule_a}) matches eventName CreateRole only: actual {len(a_overmatch)} "
        f"deliveries of other events, e.g. {json.dumps(a_overmatch[:1])[:300]!r}"
    )
    assert _iam_hits(at_q, "DeleteRole", role_name, rule_a) == [], (
        f"rule A must not deliver this role's DeleteRole: actual "
        f"{len(_iam_hits(at_q, 'DeleteRole', role_name, rule_a))}"
    )

    # ---- leg 3: the comparison region gets regional events but no IAM events -------------------------
    # TagQueue #2 is made AFTER both IAM events were delivered in us-east-1. Its arrival at the
    # comparison rule is the barrier: the channel there is live, and it has outlasted the IAM events.
    marker2 = ctx.unique_name("m2-")
    sqs_cmp.tag_queue(QueueUrl=c_url, Tags={"sim2real-marker": marker2})
    deadline = time.monotonic() + _WARM_DELIVERY_BUDGET_S
    while not _tag_hits(at_c, marker2):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the {cmp_region} rule ({rule_c}) never delivered the second "
                f"sqs:TagQueue (marker {marker2!r}) within {_WARM_DELIVERY_BUDGET_S:.0f}s, although "
                f"it delivered the first; expected 1, actual 0 of {len(at_c)} messages seen"
            )
        _collect(sqs_cmp, c_url, at_c, _LONG_POLL_S)
    tag_env = _first_tag_hits()[0]["event"]
    assert tag_env.get("source") == "aws.sqs" and tag_env.get("detail-type") == _DETAIL_TYPE, (
        f"comparison TagQueue envelope: expected source 'aws.sqs' and detail-type "
        f"{_DETAIL_TYPE!r}, actual {tag_env.get('source')!r} / {tag_env.get('detail-type')!r}"
    )
    assert tag_env.get("region") == cmp_region and (tag_env.get("detail") or {}).get(
        "awsRegion"
    ) == cmp_region, (
        f"a regional event stays in its own region: expected {cmp_region!r}, actual envelope "
        f"region {tag_env.get('region')!r}, detail.awsRegion "
        f"{(tag_env.get('detail') or {}).get('awsRegion')!r}"
    )
    hold_until = time.monotonic() + _ABSENCE_HOLD_S
    while time.monotonic() < hold_until:
        _collect(sqs_cmp, c_url, at_c, _LONG_POLL_S)
    leaked = [m for m in at_c if any(n in json.dumps(m.get("event") or {}) for n in candidates)]
    assert leaked == [], (
        f"IAM events are delivered in {_LEADER_REGION} only, so the {cmp_region} rule matching "
        f"aws.iam CreateRole/DeleteRole must deliver nothing for this run's roles "
        f"{list(candidates)!r} (subject {role_name!r}): actual "
        f"{len(leaked)}, e.g. {json.dumps(leaked[:1])[:300]!r}. That bus is demonstrably live: it "
        f"delivered both TagQueue markers, the second made after both IAM events had been "
        f"delivered in {_LEADER_REGION}"
    )

    # ---- in-body teardown of the slow pair. The cleanup chain has a 60 s ceiling, and a trail
    # bucket that CloudTrail is still writing to does not empty quickly. The registered cleanups
    # stay as idempotent safety nets.
    _delete_trail_quietly(ct, trail_arn)
    _drain_and_delete_bucket(s3, bucket, _TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
