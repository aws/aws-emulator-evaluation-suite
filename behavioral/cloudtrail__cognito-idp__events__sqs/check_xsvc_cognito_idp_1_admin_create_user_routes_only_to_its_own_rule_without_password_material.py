"""xsvc-cognito-idp-1-admin-create-user-routes-only-to-its-own-rule-without-password-material."""

# CloudTrail-sourced events reach EventBridge only while a trail logs management events.
# The CloudTrail->EventBridge hop can take many minutes to warm up and may drop writes made just
# after a trail starts, so an unrelated control write proves the channel live before any cognito
# call, and only that leg gets the cold budget.
# Neither cognito rule is narrowed to this run's pool, so positives filter by userPoolId and
# negatives are stated over eventName alone.
# The delivered AdminCreateUser record replaces username and temporaryPassword with
# HIDDEN_DUE_TO_SECURITY_REASONS and names the user by additionalEventData.sub.
# The cleanup chain has a 60 s ceiling, so the trail and bucket are torn down in the body.

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-1-admin-create-user-routes-only-to-its-own-rule-without-password-material"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-idp", "events", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_DETAIL_TYPE = "AWS API Call via CloudTrail"
_REDACTED = "HIDDEN_DUE_TO_SECURITY_REASONS"

_COLD_DELIVERY_BUDGET_S = 900.0  # control leg only, which may pay the trail's warm-up
_WARM_DELIVERY_BUDGET_S = 180.0  # every cognito leg, run after the channel is proven live
_ABSENCE_HOLD_S = 10.0  # drain after a barrier before asserting an absence
_TEARDOWN_BUDGET_S = 120.0
_CLEANUP_BUCKET_BUDGET_S = 30.0  # must fit inside the 60 s cleanup chain
_LONG_POLL_S = 5
_REEMIT_S = 120.0


def _error_code(exc):
    return exc.response.get("Error", {}).get("Code")


def _create_trail_bucket(ctx, s3, account_id):
    name = ctx.unique_name("sim2real-xsvc-ctidp-")
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default region; a LocationConstraint naming it is a 400,
        # so this literal names the API's special case, not a pinned target region.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name, _CLEANUP_BUCKET_BUDGET_S,
                                                    raise_on_leak=True))
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
    """Empty and delete the bucket until budget_s; return True once it is gone.

    The policy is removed first so CloudTrail lands no further log file. A leak raises if
    raise_on_leak, else returns False and the registered cleanup retries and raises.
    """
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if _error_code(exc) == "NoSuchBucket":
            return True
        raise
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
            message = f"s3 bucket {bucket} still not empty after {budget_s:.0f}s"
            if raise_on_leak:
                raise RuntimeError(message)
            return False
        time.sleep(3.0)


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
    name = ctx.unique_name(f"sim2real-xsvc-ctidp-{label}-")
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


def _put_rule_to_queue(ctx, events, sqs, pattern, queue_url, queue_arn):
    name = ctx.unique_name("sim2real-xsvc-ctidp-rule-")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    events.put_targets(Rule=name, Targets=[{"Id": "sink", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=name, Ids=["sink"], Force=True))
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ThisRuleOnly",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": arn}},
                        }
                    ],
                }
            )
        },
    )
    return name


def _collect(sqs, url, sink, wait_s):
    """Long-poll once for up to wait_s, then drain; append raw bodies to sink.

    Messages are deleted as read so none resurfaces as a fresh delivery in a later absence check.
    """
    wait = wait_s
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait, VisibilityTimeout=60
        ).get("Messages", [])
        if not msgs:
            return
        for m in msgs:
            sink.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        wait = 0


def _env(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def _detail(raw):
    return _env(raw).get("detail") or {}


def _named(raws, event_name):
    return [r for r in raws if _detail(r).get("eventName") == event_name]


def _for_pool(raws, event_name, pool_id):
    return [
        r
        for r in _named(raws, event_name)
        if (_detail(r).get("requestParameters") or {}).get("userPoolId") == pool_id
    ]


def _tag_hits(raws, marker):
    return [
        r
        for r in _named(raws, "TagQueue")
        if marker in json.dumps(_detail(r).get("requestParameters") or {})
    ]


def _delete_user_pool_quietly(idp, pool_id):
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if _error_code(exc) != "ResourceNotFoundException":
            raise


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """AdminCreateUser reaches its own rule with this pool's id and redacted username/password,
    with neither value anywhere in the body, and never reaches a near-miss AdminDeleteUser rule.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    idp = ctx.client("cognito-idp")

    # ---- the subject pool, created first so nothing waits on it later ---------------------------
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-ctidp-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool_quietly(idp, pool_id))

    # ---- the trail ---------------------------------------------------------------------------
    bucket = _create_trail_bucket(ctx, s3, account_id)
    trail_name = ctx.unique_name("sim2real-xsvc-ctidp-")
    trail_arn = None
    attempts = 0
    while trail_arn is None:
        attempts += 1
        try:
            trail_arn = ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket,
                IsMultiRegionTrail=False,
                IncludeGlobalServiceEvents=False,
                TagsList=[{"Key": "sim2real", "Value": CHECK}],
            )["TrailARN"]
        except ClientError as exc:
            # The bucket policy is eventually consistent; this is the only code that means "not
            # yet", and it is retried rather than asserted.
            if _error_code(exc) != "InsufficientS3BucketPolicyException" or attempts >= 30:
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _delete_trail_quietly(ct, trail_arn))
    ct.put_event_selectors(
        TrailName=trail_arn,
        EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
    )
    ct.start_logging(Name=trail_arn)
    status = ct.get_trail_status(Name=trail_arn)
    assert status.get("IsLogging") is True, (
        f"the trail must be logging before any write is made (F1): actual {status!r}"
    )

    # ---- three rules, three sinks ---------------------------------------------------------------
    ctl_url, ctl_arn = _create_queue(ctx, sqs, "ctl")
    sub_url, sub_arn = _create_queue(ctx, sqs, "sub")
    near_url, near_arn = _create_queue(ctx, sqs, "near")
    _put_rule_to_queue(
        ctx,
        events,
        sqs,
        {
            "source": ["aws.sqs"],
            "detail-type": [_DETAIL_TYPE],
            "detail": {"eventSource": ["sqs.amazonaws.com"], "eventName": ["TagQueue"]},
        },
        ctl_url,
        ctl_arn,
    )
    subject_rule = _put_rule_to_queue(
        ctx,
        events,
        sqs,
        {
            "source": ["aws.cognito-idp"],
            "detail-type": [_DETAIL_TYPE],
            "detail": {
                "eventSource": ["cognito-idp.amazonaws.com"],
                "eventName": ["AdminCreateUser"],
            },
        },
        sub_url,
        sub_arn,
    )
    near_rule = _put_rule_to_queue(
        ctx,
        events,
        sqs,
        {
            "source": ["aws.cognito-idp"],
            "detail-type": [_DETAIL_TYPE],
            "detail": {
                "eventSource": ["cognito-idp.amazonaws.com"],
                "eventName": ["AdminDeleteUser"],
            },
        },
        near_url,
        near_arn,
    )

    at_ctl, at_sub, at_near = [], [], []

    # ---- leg 1: prove the channel live with an unrelated control write -----------------------------
    markers = [ctx.unique_name("ctl-")]
    sqs.tag_queue(QueueUrl=ctl_url, Tags={"sim2real-marker": markers[-1]})
    started = time.monotonic()
    next_reemit = started + _REEMIT_S
    deadline = started + _COLD_DELIVERY_BUDGET_S

    def _control_hits():
        return [r for mk in markers for r in _tag_hits(at_ctl, mk)]

    while not _control_hits():
        if time.monotonic() >= deadline:
            st = ct.get_trail_status(Name=trail_arn)
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the CloudTrail->EventBridge channel never went live: none of "
                f"{len(markers)} sqs:TagQueue control writes (markers {markers!r}) reached the "
                f"control rule within {_COLD_DELIVERY_BUDGET_S:.0f}s; expected >=1, actual 0 of "
                f"{len(at_ctl)} messages seen. No cognito-idp call was made. Trail: "
                f"IsLogging={st.get('IsLogging')!r} "
                f"LatestDeliveryError={st.get('LatestDeliveryError')!r} "
                f"LatestDeliveryTime={st.get('LatestDeliveryTime')!r}"
            )
        if time.monotonic() >= next_reemit:
            markers.append(ctx.unique_name("ctl-"))
            sqs.tag_queue(QueueUrl=ctl_url, Tags={"sim2real-marker": markers[-1]})
            next_reemit = time.monotonic() + _REEMIT_S
        _collect(sqs, ctl_url, at_ctl, _LONG_POLL_S)
    cold_s = time.monotonic() - started
    ctl_env = _env(_control_hits()[0])
    assert ctl_env.get("source") == "aws.sqs" and ctl_env.get("detail-type") == _DETAIL_TYPE, (
        f"control envelope: expected source 'aws.sqs' and detail-type {_DETAIL_TYPE!r}, actual "
        f"{ctl_env.get('source')!r} / {ctl_env.get('detail-type')!r}"
    )
    print(f"[timing] control leg: {len(markers)} marker(s), landed after {cold_s:.1f}s")

    # ---- leg 2: AdminCreateUser, password-bearing ----------------------------------------------
    username = ctx.unique_name("sim2realuser")
    pw_token = ctx.unique_name("pwtok")
    temp_password = f"Tp1!{pw_token}"
    created = idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=temp_password,
        MessageAction="SUPPRESS",
    )["User"]
    assert created.get("Username") == username and created.get("UserStatus") == (
        "FORCE_CHANGE_PASSWORD"
    ), (
        f"AdminCreateUser with a TemporaryPassword creates the user in FORCE_CHANGE_PASSWORD: "
        f"actual Username {created.get('Username')!r}, UserStatus {created.get('UserStatus')!r}"
    )
    create_started = time.monotonic()
    deadline = create_started + _WARM_DELIVERY_BUDGET_S
    while not _for_pool(at_sub, "AdminCreateUser", pool_id):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the subject rule ({subject_rule}) never delivered "
                f"cognito-idp:AdminCreateUser for pool {pool_id!r} within "
                f"{_WARM_DELIVERY_BUDGET_S:.0f}s, although the same trail and bus delivered the "
                f"control TagQueue (channel proven live after {cold_s:.0f}s); expected 1, actual 0 "
                f"of {len(at_sub)} messages seen"
            )
        _collect(sqs, sub_url, at_sub, _LONG_POLL_S)
        _collect(sqs, near_url, at_near, 0)
    create_latency_s = time.monotonic() - create_started
    raw = _for_pool(at_sub, "AdminCreateUser", pool_id)[0]
    env = _env(raw)
    detail = env.get("detail") or {}
    params = detail.get("requestParameters") or {}
    print(f"[timing] AdminCreateUser delivered after {create_latency_s:.1f}s")

    assert env.get("source") == "aws.cognito-idp", (
        f"source: expected 'aws.cognito-idp', actual {env.get('source')!r}"
    )
    assert env.get("detail-type") == _DETAIL_TYPE, (
        f"detail-type: expected {_DETAIL_TYPE!r}, actual {env.get('detail-type')!r}"
    )
    assert detail.get("eventSource") == "cognito-idp.amazonaws.com", (
        f"detail.eventSource: expected 'cognito-idp.amazonaws.com', actual "
        f"{detail.get('eventSource')!r}"
    )
    assert detail.get("eventName") == "AdminCreateUser", (
        f"detail.eventName: expected 'AdminCreateUser', actual {detail.get('eventName')!r}"
    )
    assert env.get("account") == account_id and detail.get("recipientAccountId") == account_id, (
        f"envelope account and detail.recipientAccountId: expected {account_id!r}, actual "
        f"{env.get('account')!r} / {detail.get('recipientAccountId')!r}"
    )
    assert env.get("region") == ctx.region and detail.get("awsRegion") == ctx.region, (
        f"a regional cognito-idp event stays in its region: expected {ctx.region!r}, actual "
        f"envelope region {env.get('region')!r}, detail.awsRegion {detail.get('awsRegion')!r}"
    )
    assert detail.get("readOnly") is False and detail.get("eventCategory") == "Management", (
        f"AdminCreateUser is a write management event: expected readOnly False and "
        f"eventCategory 'Management', actual {detail.get('readOnly')!r} / "
        f"{detail.get('eventCategory')!r}"
    )
    assert params.get("userPoolId") == pool_id, (
        f"detail.requestParameters.userPoolId: expected {pool_id!r}, actual "
        f"{params.get('userPoolId')!r} (members present: {sorted(params)!r})"
    )
    # The member is kept and its value replaced, for the password and the username alike.
    assert params.get("username") == _REDACTED, (
        f"detail.requestParameters.username: expected the member present with the exact literal "
        f"{_REDACTED!r}, actual {params.get('username')!r} (members present: {sorted(params)!r})"
    )
    assert params.get("temporaryPassword") == _REDACTED, (
        f"detail.requestParameters.temporaryPassword: expected the member present with the exact "
        f"literal {_REDACTED!r}, actual {params.get('temporaryPassword')!r}"
    )
    assert params.get("messageAction") == "SUPPRESS", (
        f"a non-secret sibling member of the same request is kept verbatim: expected "
        f"requestParameters.messageAction 'SUPPRESS', actual {params.get('messageAction')!r}. "
        f"Without it, a redacted record cannot be told from one that redacts everything"
    )
    user_sub = {a["Name"]: a["Value"] for a in created.get("Attributes", [])}.get("sub")
    assert user_sub and (detail.get("additionalEventData") or {}).get("sub") == user_sub, (
        f"with the username hidden, the record names the user by sub: expected "
        f"additionalEventData.sub == {user_sub!r} (from the AdminCreateUser response), actual "
        f"{(detail.get('additionalEventData') or {}).get('sub')!r}"
    )
    user_el = (detail.get("responseElements") or {}).get("user") or {}
    assert user_el.get("username") == _REDACTED and user_el.get("userStatus") == (
        "FORCE_CHANGE_PASSWORD"
    ), (
        f"detail.responseElements.user: expected username {_REDACTED!r} and userStatus "
        f"'FORCE_CHANGE_PASSWORD', actual {user_el.get('username')!r} / "
        f"{user_el.get('userStatus')!r}"
    )
    assert username not in raw, (
        f"the plaintext username {username!r} appears in the delivered message; real AWS "
        f"redacts it everywhere in this record"
    )
    assert pw_token not in raw, (
        f"the temporary password's run-unique token {pw_token!r} appears in the message "
        f"EventBridge delivered for AdminCreateUser. A credential sent to Cognito seconds ago is "
        f"now readable by every subscriber of this rule"
    )

    # ---- leg 3: AdminDeleteUser -- the near-miss rule's positive control ----------------------------
    idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    deadline = time.monotonic() + _WARM_DELIVERY_BUDGET_S
    while not _for_pool(at_near, "AdminDeleteUser", pool_id):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the near-miss rule ({near_rule}) never delivered "
                f"cognito-idp:AdminDeleteUser for pool {pool_id!r} within "
                f"{_WARM_DELIVERY_BUDGET_S:.0f}s, although the subject rule delivered the create "
                f"in {create_latency_s:.0f}s; expected 1, actual 0 of {len(at_near)} messages"
            )
        _collect(sqs, near_url, at_near, _LONG_POLL_S)
        _collect(sqs, sub_url, at_sub, 0)
    del_env = _env(_for_pool(at_near, "AdminDeleteUser", pool_id)[0])
    assert del_env.get("source") == "aws.cognito-idp" and del_env.get("detail-type") == (
        _DETAIL_TYPE
    ), (
        f"AdminDeleteUser envelope: expected source 'aws.cognito-idp' and detail-type "
        f"{_DETAIL_TYPE!r}, actual {del_env.get('source')!r} / {del_env.get('detail-type')!r}"
    )
    del_detail = del_env.get("detail") or {}
    assert (del_detail.get("additionalEventData") or {}).get("sub") == user_sub and (
        (del_detail.get("requestParameters") or {}).get("username") == _REDACTED
    ), (
        f"the delete names the SAME user by sub, with the username hidden: expected sub "
        f"{user_sub!r} and username {_REDACTED!r}, actual "
        f"{(del_detail.get('additionalEventData') or {}).get('sub')!r} / "
        f"{(del_detail.get('requestParameters') or {}).get('username')!r}"
    )

    # Both sinks keep draining a while longer before the absences are asserted.
    hold_until = time.monotonic() + max(_ABSENCE_HOLD_S, create_latency_s)
    while time.monotonic() < hold_until:
        _collect(sqs, near_url, at_near, _LONG_POLL_S)
        _collect(sqs, sub_url, at_sub, _LONG_POLL_S)
    near_creates = _named(at_near, "AdminCreateUser")
    assert near_creates == [], (
        f"the near-miss rule ({near_rule}) matches eventName AdminDeleteUser only, so its sink "
        f"must hold no AdminCreateUser for any pool: actual {len(near_creates)}, e.g. "
        f"{near_creates[:1]!r}. Its wiring was live: it delivered this run's AdminDeleteUser, "
        f"which was issued only after the create had reached the subject rule"
    )
    near_other = [r for r in at_near if _detail(r).get("eventName") != "AdminDeleteUser"]
    assert near_other == [], (
        f"the near-miss sink must hold nothing but AdminDeleteUser: actual {len(near_other)} "
        f"other envelopes, e.g. {near_other[:1]!r}"
    )
    sub_deletes = _named(at_sub, "AdminDeleteUser")
    assert sub_deletes == [], (
        f"the subject rule ({subject_rule}) matches eventName AdminCreateUser only, so its sink "
        f"must hold no AdminDeleteUser for any pool: actual {len(sub_deletes)}, e.g. "
        f"{sub_deletes[:1]!r}"
    )
    stray_at_ctl = [r for r in at_ctl if _env(r).get("source") == "aws.cognito-idp"]
    assert stray_at_ctl == [], (
        f"the control rule matches aws.sqs only, so its sink must hold no aws.cognito-idp "
        f"event: actual {len(stray_at_ctl)}"
    )

    # ---- in-body teardown of the slow pair ----------------------------------------------------------
    _delete_trail_quietly(ct, trail_arn)
    _drain_and_delete_bucket(s3, bucket, _TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
