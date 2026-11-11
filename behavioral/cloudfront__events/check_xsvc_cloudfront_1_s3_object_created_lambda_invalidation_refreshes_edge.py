"""xsvc-cloudfront-1-s3-object-created-lambda-invalidation-refreshes-edge."""

from __future__ import annotations

import io
import json
import ssl
import textwrap
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-1-s3-object-created-lambda-invalidation-refreshes-edge"
GROUP = "e2e"
SERVICES = ["cloudfront", "events"]

# CloudFront's control plane and CloudTrail records live in us-east-1, and so does every resource
# here (bucket, Lambda, rules, sinks, trail) so the whole chain is one region. This literal names
# CloudFront's control-plane/CloudTrail region; it is not a pinned target region.
_EVENT_REGION = "us-east-1"
# Readiness barrier budget (never asserted as a latency) vs the warm per-leg budget; see the
# sibling xsvc-cloudfront-1-* checks. Body worst case is dominated by the two CloudFront deploys.
_READY_BUDGET_S = 600.0
_DELIVERY_BUDGET_S = 180.0
_DEPLOY_BUDGET_S = 900.0
_ORIGIN_BUDGET_S = 300.0
_COMPLETE_BUDGET_S = 600.0
_HOLD_FLOOR_S = 30.0
_HOLD_CAP_S = 120.0
_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"  # AWS-managed cache policy


_LAMBDA_SOURCE = textwrap.dedent(
    """
    import os
    import time

    import boto3
    from botocore.exceptions import ClientError

    CF = boto3.client("cloudfront")


    def handler(event, context):
        key = event["detail"]["object"]["key"]
        deadline = time.time() + 75
        while True:
            try:
                inv = CF.create_invalidation(
                    DistributionId=os.environ["DIST_ID"],
                    InvalidationBatch={
                        "CallerReference": key,
                        "Paths": {"Quantity": 1, "Items": [os.environ["PATH_TO_INVALIDATE"]]},
                    },
                )
                return {"invalidation": inv["Invalidation"]["Id"]}
            except ClientError as exc:
                # IAM propagation: a role minted seconds ago can be denied on first use.
                if exc.response["Error"]["Code"] != "AccessDenied" or time.time() > deadline:
                    raise
                time.sleep(5)
    """
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """S3 Object Created -> EventBridge -> Lambda -> CreateInvalidation: the edge serves stale bytes
    after an untriggered overwrite and the new bytes once the invalidation completes; the call is a
    CloudTrail event attributed to the Lambda's role, and completion emits no event.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3", region=_EVENT_REGION)
    cf = ctx.client("cloudfront", region=_EVENT_REGION)
    iam = ctx.client("iam")
    lam = ctx.client("lambda", region=_EVENT_REGION)
    logs = ctx.client("logs", region=_EVENT_REGION)
    events = ctx.client("events", region=_EVENT_REGION)

    # --- origin: private bucket, EventBridge notifications on ---------------------------------
    bucket = ctx.unique_name("sim2real-xsvc-cforigin-")
    s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    v1 = ctx.unique_name("sim2real-bytes-v1-")
    v2 = ctx.unique_name("sim2real-bytes-v2-")
    s3.put_object(Bucket=bucket, Key="page.txt", Body=v1.encode(), ContentType="text/plain")

    # --- distribution behind OAC ----------------------------------------------------------------
    oac_id = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-xsvc-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac_quietly(cf, oac_id))
    ref = ctx.unique_name("sim2real-xsvc-cfchain-")
    dist = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ref,
                "Comment": "sim2real xsvc cloudfront__events chain check",
                "Enabled": True,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "s3origin",
                            "DomainName": f"{bucket}.s3.amazonaws.com",
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                            "OriginAccessControlId": oac_id,
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "s3origin",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
                },
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )["Distribution"]
    dist_id, dist_arn, domain = dist["Id"], dist["ARN"], dist["DomainName"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist_id, 900.0))
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudfront.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                        "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
                    }
                ],
            }
        ),
    )

    # --- Lambda that invalidates, behind an aws.s3 Object Created rule ------------------------
    fn_name = ctx.unique_name("sim2real-xsvc-cfinv-fn-")
    role_name = ctx.unique_name("sim2real-xsvc-cfinv-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="invalidate",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": dist_arn},
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="invalidate"))
    # Registered BEFORE the function exists so LIFO runs it AFTER delete_function: an invocation's
    # buffered log stream can recreate the group after the delete, so it is reaped in a loop.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
    fn_arn = _create_function(ctx, lam, fn_name, role_arn, dist_id)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    s3_rule = ctx.unique_name("sim2real-xsvc-cfs3-rule-")
    s3_rule_arn = events.put_rule(
        Name=s3_rule,
        EventPattern=json.dumps(
            {
                "source": ["aws.s3"],
                "detail-type": ["Object Created"],
                "detail": {"bucket": {"name": [bucket]}, "object": {"key": [{"prefix": "trigger/"}]}},
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=s3_rule, Force=True))
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="allow-s3-rule",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=s3_rule_arn,
    )
    events.put_targets(Rule=s3_rule, Targets=[{"Id": "fn", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=s3_rule, Ids=["fn"], Force=True))

    # --- CloudTrail-side sinks: the API-call record, and EVERY aws.cloudfront event ------------
    ct_url, _ = _sink(
        ctx,
        "chainct",
        [
            (
                {
                    "source": ["aws.cloudfront"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateInvalidation"]},
                },
                "ENABLED",
            )
        ],
    )
    all_url, _ = _sink(ctx, "chainall", [({"source": ["aws.cloudfront"]}, "ENABLED")])
    ct, trail_arn = _start_trail(ctx)  # created LAST so LIFO teardown removes it FIRST

    # --- the distribution serves v1, from cache ---------------------------------------------
    deadline = _deadline(ctx, _DEPLOY_BUDGET_S)
    while cf.get_distribution(Id=dist_id)["Distribution"]["Status"] != "Deployed":
        assert time.monotonic() < deadline, (
            f"distribution {dist_id} did not reach Deployed within {_DEPLOY_BUDGET_S:.0f}s"
        )
        time.sleep(_POLL_INTERVAL_S)
    seen: dict[str, list] = {}
    _await_sinks_live(ctx, [ct_url, all_url], seen)
    ct_seen, all_seen = list(seen[ct_url]), list(seen[all_url])

    url, route_headers = ctx.endpoint_route(f"{domain}/page.txt")
    status, body, _ = _poll_get(url, route_headers, v1, _deadline(ctx, _ORIGIN_BUDGET_S), verify=ctx.http_verify)
    assert (status, body) == (200, v1), (
        f"first viewer GET through the distribution: expected (200, {v1!r}), actual "
        f"({status!r}, {body!r})"
    )
    status, body, xcache = _get(url, route_headers, verify=ctx.http_verify)
    assert (status, body) == (200, v1) and xcache.startswith("Hit"), (
        f"second viewer GET must be a cache hit on v1: expected (200, {v1!r}, 'Hit from "
        f"cloudfront'), actual ({status!r}, {body!r}, {xcache!r})"
    )

    # --- overwrite the origin WITHOUT a trigger: the edge keeps serving stale bytes -------------
    s3.put_object(Bucket=bucket, Key="page.txt", Body=v2.encode(), ContentType="text/plain")
    status, body, xcache = _get(url, route_headers, verify=ctx.http_verify)
    assert (status, body) == (200, v1), (
        f"after the origin was overwritten and BEFORE any invalidation, the edge must still serve "
        f"the cached v1: expected (200, {v1!r}), actual ({status!r}, {body!r}, x-cache {xcache!r})"
    )
    none_yet = cf.list_invalidations(DistributionId=dist_id)["InvalidationList"].get("Quantity")
    assert none_yet == 0, (
        f"an overwrite of a non-trigger key must not invalidate anything: expected 0 "
        f"invalidations, actual {none_yet!r}"
    )

    # --- the trigger: S3 -> EventBridge -> Lambda -> CreateInvalidation -----------------------
    trigger_key = f"trigger/{ctx.unique_name('t-')}.json"
    s3.put_object(Bucket=bucket, Key=trigger_key, Body=b"{}", ContentType="application/json")
    deadline = _deadline(ctx, _DELIVERY_BUDGET_S)
    while True:
        items = cf.list_invalidations(DistributionId=dist_id)["InvalidationList"].get("Items", [])
        if items:
            break
        assert time.monotonic() < deadline, (
            f"no invalidation appeared on {dist_id} within {_DELIVERY_BUDGET_S:.0f}s of putting "
            f"{trigger_key!r}: the S3 Object Created -> rule -> Lambda chain did not fire"
        )
        time.sleep(_POLL_INTERVAL_S)
    assert len(items) == 1, (
        f"one trigger object must produce exactly one invalidation: expected 1, actual "
        f"{[i['Id'] for i in items]!r}"
    )
    inv_id = items[0]["Id"]
    inv = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)["Invalidation"]
    batch = inv["InvalidationBatch"]
    assert (batch["CallerReference"], batch["Paths"].get("Items")) == (trigger_key, ["/page.txt"]), (
        f"the Lambda's invalidation must name the trigger key and the bytes path: expected "
        f"({trigger_key!r}, ['/page.txt']), actual ({batch['CallerReference']!r}, "
        f"{batch['Paths'].get('Items')!r})"
    )

    # --- completion, then the NEW bytes ----------------------------------------------------------
    deadline = _deadline(ctx, _COMPLETE_BUDGET_S)
    while True:
        status_now = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)["Invalidation"]["Status"]
        if status_now == "Completed":
            break
        assert time.monotonic() < deadline, (
            f"invalidation {inv_id} did not reach Completed within {_COMPLETE_BUDGET_S:.0f}s; "
            f"last status {status_now!r}"
        )
        time.sleep(_POLL_INTERVAL_S)
    completed_at = time.monotonic()
    status, body, xcache = _poll_get(url, route_headers, v2, _deadline(ctx, 60.0), verify=ctx.http_verify)
    assert (status, body) == (200, v2), (
        f"after invalidation {inv_id} Completed the edge must serve the NEW bytes: expected "
        f"(200, {v2!r}), actual ({status!r}, {body!r}, x-cache {xcache!r})"
    )

    # --- the CreateInvalidation API call is an event, attributed to the Lambda -----------------
    def _the_call(e):
        d = e.get("detail") or {}
        return ((d.get("responseElements") or {}).get("invalidation") or {}).get("id") == inv_id

    env = _await_envelope(ctx, ct_url, ct_seen, _the_call, f"CreateInvalidation {inv_id}")
    detail = env.get("detail") or {}
    assert (env.get("source"), env.get("detail-type"), detail.get("eventName")) == (
        "aws.cloudfront",
        "AWS API Call via CloudTrail",
        "CreateInvalidation",
    ), (
        "the invalidation's API call must arrive as ('aws.cloudfront', 'AWS API Call via "
        f"CloudTrail', 'CreateInvalidation'): actual ({env.get('source')!r}, "
        f"{env.get('detail-type')!r}, {detail.get('eventName')!r})"
    )
    assert (detail.get("requestParameters") or {}).get("distributionId") == dist_id, (
        f"requestParameters.distributionId: expected {dist_id!r}, actual "
        f"{(detail.get('requestParameters') or {}).get('distributionId')!r}"
    )
    caller = (detail.get("userIdentity") or {}).get("arn", "")
    assert f":assumed-role/{role_name}/" in caller, (
        f"the call was made by the Lambda, so userIdentity.arn must be its assumed role "
        f"{role_name!r}: actual {caller!r} (account {account_id})"
    )

    # --- completion fires NOTHING: a post-completion write is the barrier, held one more ---
    # --- measured latency past its own arrival before the absence is graded -------------------
    tag_rid = cf.tag_resource(
        Resource=dist_arn, Tags={"Items": [{"Key": "sim2real-after-completion", "Value": inv_id}]}
    )["ResponseMetadata"]["RequestId"]
    _await_envelope(
        ctx,
        all_url,
        all_seen,
        lambda e: (e.get("detail") or {}).get("requestID") == tag_rid,
        "post-completion TagResource on the every-aws.cloudfront sink",
    )
    # Absence barrier: hold for one more measured latency (the barrier's own, floor/cap clamped)
    # past its confirmed arrival, since EventBridge delivery is not FIFO and a completion event
    # could still land after the barrier if we stopped collecting the instant it was seen.
    hold_s = min(max(time.monotonic() - completed_at, _HOLD_FLOOR_S), _HOLD_CAP_S)
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    hold_deadline = time.monotonic() + hold_s
    while time.monotonic() < hold_deadline:
        all_seen.extend(_drain(sqs, all_url))
        time.sleep(_POLL_INTERVAL_S)
    about_inv = sorted(
        {
            (e.get("detail-type"), (e.get("detail") or {}).get("eventName"))
            for e in all_seen
            if not _is_barrier(e) and inv_id in json.dumps(e.get("detail"))
            and (e.get("detail") or {}).get("requestID") != tag_rid
        }
    )
    assert about_inv == [("AWS API Call via CloudTrail", "CreateInvalidation")], (
        "the ONLY aws.cloudfront event about this invalidation must be its CreateInvalidation API "
        f"call -- completion is not an event, held {hold_s:.0f}s past the barrier: expected "
        f"[('AWS API Call via CloudTrail', 'CreateInvalidation')], actual {about_inv!r}"
    )
    kinds = sorted({e.get("detail-type") for e in all_seen if not _is_barrier(e)})
    assert kinds == ["AWS API Call via CloudTrail"], (
        "every aws.cloudfront event seen across the whole lifecycle must be an API-call record: "
        f"expected ['AWS API Call via CloudTrail'], actual {kinds!r}"
    )

    _delete_trail_quietly(ct, trail_arn)
    _retire_distribution(cf, dist_id, 900.0)
    _delete_oac_quietly(cf, oac_id)


def _get(url, route_headers, verify=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-check", **route_headers})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_https_context(verify)) as resp:  # noqa: S310
            return resp.status, resp.read().decode(), resp.headers.get("X-Cache", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:200], exc.headers.get("X-Cache", "")


def _deadline(ctx, seconds):
    """A monotonic deadline of `seconds`, capped by the run's remaining budget."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _poll_get(url, route_headers, want, deadline, verify=True):
    last = None
    while True:
        try:
            last = _get(url, route_headers, verify=verify)
            if last[:2] == (200, want):
                return last
        except (urllib.error.URLError, TimeoutError) as exc:
            last = (None, repr(exc), "")
        if time.monotonic() >= deadline:
            return last
        time.sleep(2.0)


def _create_function(ctx, lam, fn_name, role_arn, dist_id):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _LAMBDA_SOURCE)
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=90,
                Environment={"Variables": {"DIST_ID": dist_id, "PATH_TO_INVALIDATE": "/page.txt"}},
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException:
            # IAM propagation: Lambda cannot yet assume a role minted seconds ago.
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    deadline = time.monotonic() + 60.0
    while lam.get_function_configuration(FunctionName=fn_name)["State"] != "Active":
        assert time.monotonic() < deadline, f"lambda {fn_name} never became Active"
        time.sleep(2.0)
    return arn


def _reap_log_group(logs, name):
    """delete_function leaves /aws/lambda/<fn>, and a late flush can recreate it: delete, then
    watch for reappearance over a bounded window, and raise rather than hang."""
    deadline = time.monotonic() + 15.0
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        if not any(g["logGroupName"] == name for g in groups):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {name} keeps reappearing")


def _delete_oac_quietly(cf, oac_id, budget_s=120.0):
    """Delete the OAC, retrying OriginAccessControlInUse while a just-deleted distribution
    releases it; any other refusal, or still in use after budget_s, raises."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
            cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchOriginAccessControl":
                return
            if code != "OriginAccessControlInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


_POLL_INTERVAL_S = 2.0
_BUCKET_DRAIN_BUDGET_S = 30.0
_BARRIER_PATTERN = {
    "source": ["aws.cloudfront"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {"eventName": ["UpdateOriginAccessControl"]},
}
_BARRIER_KEY = "sim2real-barrier-"


def _start_trail(ctx):
    """A single-region us-east-1 trail recording global-service (CloudFront) management events,
    logging before any trigger fires. Returns (cloudtrail client, trail ARN)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3", region=_EVENT_REGION)
    ct = ctx.client("cloudtrail", region=_EVENT_REGION)
    bucket = ctx.unique_name("sim2real-xsvc-cfct-")
    # us-east-1 is CreateBucket's default; a LocationConstraint naming it is itself a 400.
    s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )
    trail_arn = ct.create_trail(
        Name=ctx.unique_name("sim2real-xsvc-cfct-"),
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=True,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail_quietly(ct, trail_arn))
    ct.start_logging(Name=trail_arn)
    logging = ct.get_trail_status(Name=trail_arn).get("IsLogging")
    assert logging is True, (
        f"the trail must be logging before any trigger fires: expected True, actual {logging!r}"
    )
    return ct, trail_arn


def _delete_trail_quietly(ct, trail_arn):
    try:
        ct.delete_trail(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


def _drain_and_delete_bucket(s3, bucket):
    """CloudTrail can land a log file after the trail is gone, so drain-then-delete in a bounded
    loop and say so on stderr if it never converges."""
    deadline = time.monotonic() + _BUCKET_DRAIN_BUDGET_S
    while True:
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        for i in range(0, len(keys), 1000):
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
            ).get("Errors")
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
            raise RuntimeError(f"trail bucket {bucket} not empty after drain")
        time.sleep(5.0)


def _sink(ctx, label, patterns):
    """An SQS sink behind one rule per (pattern, state) PLUS a barrier rule on CloudFront
    UpdateOriginAccessControl that targets the SAME sink, with one queue policy admitting all of
    them. Returns (url, subject rule names)."""
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    events = ctx.client("events", region=_EVENT_REGION)
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-xsvc-cf-{label}-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    names, arns = [], []
    for pattern, state in list(patterns) + [(_BARRIER_PATTERN, "ENABLED")]:
        name = ctx.unique_name("sim2real-xsvc-cf-rule-")
        arns.append(
            events.put_rule(
                Name=name,
                EventPattern=json.dumps(pattern),
                State=state,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )["RuleArn"]
        )
        ctx.on_cleanup(lambda n=name: events.delete_rule(Name=n, Force=True))
        events.put_targets(Rule=name, Targets=[{"Id": "sink", "Arn": arn}])
        ctx.on_cleanup(lambda n=name: events.remove_targets(Rule=n, Ids=["sink"], Force=True))
        names.append(name)
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": a}},
                        }
                        for a in arns
                    ],
                }
            )
        },
    )
    return url, names[:-1]


def _drain(sqs, url):
    """Every message currently visible, parsed and DELETED, so a once-seen message cannot
    resurface after its visibility timeout and be mistaken for a fresh delivery."""
    out = []
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=60
        ).get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _is_barrier(env):
    detail = env.get("detail") or {}
    return detail.get("eventName") == "UpdateOriginAccessControl" and _BARRIER_KEY in json.dumps(
        detail
    )


def _await_sinks_live(ctx, urls, seen):
    """Readiness barrier, not a latency assertion: update a barrier OAC every 30s until its record
    reaches EVERY sink, so a later absence is a routing verdict. A fresh trail's first delivery can
    take minutes and earlier records are never delivered, so the budget is generous."""
    cf = ctx.client("cloudfront", region=_EVENT_REGION)
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    oac_id = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name(_BARRIER_KEY),
            "Description": "sim2real readiness barrier",
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_barrier_oac(cf, oac_id))
    pending = set(urls)
    started = time.monotonic()
    last_fire = -1e9
    markers: set[str] = set()
    while pending:
        if time.monotonic() - last_fire >= 30.0:
            got = cf.get_origin_access_control(Id=oac_id)
            cfg = got["OriginAccessControl"]["OriginAccessControlConfig"]
            marker = ctx.unique_name(_BARRIER_KEY)
            markers.add(marker)
            cfg["Description"] = marker
            cf.update_origin_access_control(
                Id=oac_id, IfMatch=got["ETag"], OriginAccessControlConfig=cfg
            )
            last_fire = time.monotonic()
        time.sleep(_POLL_INTERVAL_S)
        for u in list(pending):
            got_envs = _drain(sqs, u)
            seen.setdefault(u, []).extend(got_envs)
            if any(_is_barrier(e) and any(m in json.dumps(e["detail"]) for m in markers)
                   for e in got_envs):
                pending.discard(u)
        if pending and time.monotonic() - started >= _READY_BUDGET_S:
            raise AssertionError(
                f"CHANNEL NOT LIVE (not a routing verdict): no CloudFront UpdateOriginAccessControl "
                f"record reached {len(pending)} sink(s) within {_READY_BUDGET_S:.0f}s of the trail "
                f"starting to log: {sorted(pending)!r}"
            )
    _delete_barrier_oac(cf, oac_id)
    return time.monotonic() - started


def _delete_barrier_oac(cf, oac_id):
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchOriginAccessControl":
            raise


def _await_envelope(ctx, url, seen, predicate, what):
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    deadline = _deadline(ctx, _DELIVERY_BUDGET_S)
    while True:
        seen.extend(_drain(sqs, url))
        hits = [e for e in seen if predicate(e)]
        if hits:
            return hits[0]
        if time.monotonic() >= deadline:
            names = [(e.get("detail") or {}).get("eventName") for e in seen]
            raise AssertionError(
                f"{what} did not arrive within {_DELIVERY_BUDGET_S:.0f}s of a channel proven "
                f"live; the sink saw {len(seen)} other envelope(s) naming {names!r}"
            )
        time.sleep(_POLL_INTERVAL_S)


def _retire_distribution(cf, dist_id, budget_s):
    """Disable if needed, wait for Deployed, delete; raise if it is still not gone after budget_s.
    Called from the body and again as the cleanup net for the failure path."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
                return
            raise
        dist = got["Distribution"]
        if dist["DistributionConfig"]["Enabled"]:
            cfg = cf.get_distribution_config(Id=dist_id)
            body = cfg["DistributionConfig"]
            body["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=body, IfMatch=cfg["ETag"])
            continue
        if dist["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=got["ETag"])
            return
        if time.monotonic() >= deadline:
            message = (
                f"distribution {dist_id} still {dist['Status']} after {budget_s:.0f}s; it is "
                "disabled and tagged sim2real"
            )
            raise RuntimeError(message)
        time.sleep(2.0)

def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
