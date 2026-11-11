"""config-item-change-notification-diff-names-the-changed-field."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# A fresh recorder discovering every resource type at once can delay notifications for minutes.
_NOTIFICATION_BUDGET_S = 600.0

#: Tolerance when comparing a service-stamped notification time against this process's clock.
_CLOCK_SKEW_S = 120.0

_INITIAL_TIMEOUT = "31"
_CHANGED_TIMEOUT = "41"

_CONFIG_ROLE_NAME = "sim2real-behav-config-role"
_CONFIG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

# Three transitions plus IAM propagation plus Config's low control-plane burst limit need
# more than 300 s.
_TRANSITION_BUDGET_S = 360.0

_S3_DELIVERY_BUCKET_POLICY = """{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::{bucket}"
    }},
    {{
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::{bucket}"
    }},
    {{
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::{bucket}/*",
      "Condition": {{"StringEquals": {{"s3:x-amz-acl": "bucket-owner-full-control"}}}}
    }}
  ]
}}"""


def _error_code(fn):
    """The AWS error code raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _error_code_or_none(fn):
    """The error code raised by fn(), or None on success. For polling only, never asserted."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _capped(ctx, budget_s):
    """*budget_s*, capped by the time the run has left so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(0.0, left - 10.0))


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/delivery-channels
    # across checks reliably trips ThrottlingException. Retry those transparently while re-raising
    # any domain error a check asserts on.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    """A bounded retry with a stated reason that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _trusts_config_service(doc):
    """True only if the trust policy names exactly config.amazonaws.com (a substring test
    would also match a service-linked role Config cannot assume for recording/delivery)."""
    import urllib.parse as _up

    if isinstance(doc, str):
        try:
            doc = json.loads(_up.unquote(doc))
        except (ValueError, TypeError):
            return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        svc = principal.get("Service") if isinstance(principal, dict) else None
        svcs = svc if isinstance(svc, list) else [svc]
        if "config.amazonaws.com" in svcs:
            return True
    return False


def _ensure_config_role(ctx):
    """Resolve one fixed-name recorder role, creating it if absent.
    Not a scan for any role trusting config.amazonaws.com, which could adopt another check's
    deliberately broken role; that scan is only a fallback when iam:CreateRole is denied."""
    global _ROLE_ARN_CACHE
    if _ROLE_ARN_CACHE:
        return _ROLE_ARN_CACHE
    iam = ctx.client("iam")
    arn = None
    try:
        role = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]
        assert _trusts_config_service(role.get("AssumeRolePolicyDocument")), (
            f"{_CONFIG_ROLE_NAME!r} exists but does not trust config.amazonaws.com, so no recorder "
            f"built on it can record: {role!r}"
        )
        arn = role["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    if not arn:
        try:
            arn = iam.create_role(
                RoleName=_CONFIG_ROLE_NAME,
                AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
                Description="sim2real behavioral fidelity probe role for AWS Config",
                Tags=[{"Key": "sim2real", "Value": "config-recorder-role"}],
            )["Role"]["Arn"]
            iam.attach_role_policy(
                RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityAlreadyExists":
                arn = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
            elif code in ("AccessDenied", "AccessDeniedException"):
                for page in iam.get_paginator("list_roles").paginate():
                    for role in page.get("Roles", []):
                        if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
                            arn = role["Arn"]
                            break
                    if arn:
                        break
                if not arn:
                    raise AssertionError(
                        "no AWS Config service role is available in this account and the caller "
                        "lacks iam:CreateRole, so no configuration recorder can be created"
                    ) from exc
            else:
                raise
    _ROLE_ARN_CACHE = arn
    return arn


def _clear_recorders(ctx):
    """Config allows one recorder per account and Region, so a leftover one makes
    PutConfigurationRecorder fail MaxNumberOfConfigurationRecordersExceededException."""
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(
                lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass


def _clear_delivery_channels(ctx):
    """The delivery channel is the recorder's twin singleton (one per account and Region)."""
    cfg = ctx.client("config")
    try:
        chans = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except ClientError:
        return
    for ch in chans:
        try:
            cfg.delete_delivery_channel(DeliveryChannelName=ch.get("name"))
        except ClientError:
            pass


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    # A versioned bucket needs every version AND every delete marker removed, else delete_bucket
    # fails BucketNotEmpty; list_objects_v2 alone never sees them.
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", [])):
                try:
                    s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                try:
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_bucket(ctx, prefix, scenario):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix).replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint naming itself; every other region
        # requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}
    )
    return bucket


def _create_delivery_bucket(ctx, scenario):
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, "sim2real-behav-cfg-delivery-", scenario)
    s3.put_bucket_policy(Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket))
    return bucket


def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    # PutConfigurationRecorder validates that Config can assume the role, which fails until a
    # freshly created role has propagated, so it is retried until a deadline.
    deadline = time.monotonic() + _capped(ctx, 180.0)
    while True:
        try:
            _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder))
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InsufficientPermissionsException", "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _recorder_status(ctx, name):
    cfg = ctx.client("config")
    statuses = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    )["ConfigurationRecordersStatus"]
    return statuses[0] if statuses else None


def _all_recorder_statuses(ctx):
    cfg = ctx.client("config")
    try:
        return [
            {
                k: s.get(k)
                for k in ("name", "recording", "lastStatus", "lastErrorCode", "lastErrorMessage")
            }
            for s in cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        ]
    except ClientError as exc:
        return f"unreadable: {exc}"


def _start_recorder(ctx, name, register_cleanup=True):
    """Start the recorder and wait until it reports recording=True.

    Not gated on lastStatus == 'SUCCESS': it can stay PENDING for over 300 s on a fresh
    recorder while configuration items are already being produced."""
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    if register_cleanup:
        ctx.on_cleanup(
            lambda: _retry_throttled(
                lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
            )
        )
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is True,
        timeout_s=_capped(ctx, _TRANSITION_BUDGET_S),
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=_capped(ctx, _TRANSITION_BUDGET_S),
        interval_s=2,
        description=f"recorder {name!r} reports recording=False",
    )


def _create_delivery_channel(ctx, name, bucket, sns_topic_arn=None, delivery_frequency=None):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    if sns_topic_arn:
        channel["snsTopicARN"] = sns_topic_arn
    if delivery_frequency:
        channel["configSnapshotDeliveryProperties"] = {"deliveryFrequency": delivery_frequency}
    # The freshly-written bucket policy is eventually consistent; Config rejects a delivery channel
    # whose bucket policy has not propagated with InsufficientDeliveryPolicyException.
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=channel))
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_delivery_channel(DeliveryChannelName=name)
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InsufficientDeliveryPolicyException":
                raise
            last = exc
            time.sleep(3 * (attempt + 1))
    raise last


def _start_recording(ctx, scenario, recording_group=None, sns_topic_arn=None):
    """Create a delivery bucket with the Config delivery policy, a delivery channel and a
    running recorder. Returns (recorder, channel, bucket)."""
    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)
    bucket = _create_delivery_bucket(ctx, scenario)
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder, recording_group=recording_group)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket, sns_topic_arn=sns_topic_arn)
    _start_recorder(ctx, recorder)
    return recorder, channel, bucket


def _history_items(ctx, resource_type, resource_id):
    """Every configuration item Config holds for a resource, paginated.
    ResourceNotDiscoveredException is treated as an empty history."""
    cfg = ctx.client("config")
    items = []
    try:
        for page in cfg.get_paginator("get_resource_config_history").paginate(
            resourceType=resource_type, resourceId=resource_id
        ):
            items.extend(page["configurationItems"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotDiscoveredException":
            return []
        raise
    return items


def _await_history_items(ctx, resource_type, resource_id, *, timeout_s, predicate=None,
                         description=None):
    """Poll for configuration items; on timeout, report the recorder's own status so a stalled
    recorder is distinguishable from an unrecorded resource."""
    predicate = predicate or (lambda items: bool(items))
    description = description or f"a configuration item for {resource_type} {resource_id!r}"
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = _retry_throttled(lambda: _history_items(ctx, resource_type, resource_id))
        if predicate(last):
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


def _create_queue(ctx, scenario, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cfg-q-").replace("_", "-")
    kwargs = {"QueueName": name, "tags": {"sim2real": scenario}}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


def _create_notification_topic(ctx, scenario, account):
    """An SNS topic Config is allowed to publish to. The topic policy is written in full - replacing
    it drops the default owner statement, so the owner grant is re-stated here explicitly."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-cfg-topic-").replace("_", "-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": scenario}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    sns.set_topic_attributes(
        TopicArn=arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowOwnerFullControl",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        # SNS's access-policy language rejects a wildcard action ("Policy statement
                        # action out of service scope!"); it must be the enumerated action list.
                        "Action": [
                            "SNS:GetTopicAttributes",
                            "SNS:SetTopicAttributes",
                            "SNS:AddPermission",
                            "SNS:RemovePermission",
                            "SNS:DeleteTopic",
                            "SNS:Subscribe",
                            "SNS:ListSubscriptionsByTopic",
                            "SNS:Publish",
                            "SNS:Receive",
                        ],
                        "Resource": arn,
                    },
                    {
                        "Sid": "AllowConfigPublish",
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "SNS:Publish",
                        "Resource": arn,
                        "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                    },
                ],
            }
        ),
    )
    return arn


def _subscribe_queue(ctx, topic_arn, scenario):
    """A queue subscribed to the topic, with the queue policy SNS needs to deliver into it. Returns
    (queue_url, queue_arn)."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    _name, url = _create_queue(ctx, scenario)
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowSnsDelivery",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn, ReturnSubscriptionArn=True)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub["SubscriptionArn"]))
    return url, arn


def _drain_notifications(ctx, queue_url, *, timeout_s, predicate, description, seen=None):
    """Long-poll the sink queue, accumulating every (envelope, message) pair, until predicate(seen)
    holds. The 20s WaitTimeSeconds is the wait; the loop is bounded and raises on timeout."""
    sqs = ctx.client("sqs")
    seen = seen if seen is not None else []
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=20, VisibilityTimeout=60
        )
        for raw in resp.get("Messages", []):
            envelope = json.loads(raw["Body"])
            body = envelope.get("Message")
            try:
                message = json.loads(body) if isinstance(body, str) else body
            except ValueError:
                message = None
            seen.append((envelope, message))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=raw["ReceiptHandle"])
        if predicate(seen):
            return seen
    seen_resources = [
        (
            (m.get("configurationItem") or {}).get("resourceType"),
            (m.get("configurationItem") or {}).get("resourceId"),
        )
        for _e, m in seen
        if isinstance(m, dict)
    ]
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Saw {len(seen)} notification(s) with "
        f"messageTypes "
        f"{[m.get('messageType') if isinstance(m, dict) else None for _e, m in seen]!r} for "
        f"resources {seen_resources!r}. "
        f"Recorder status: {_all_recorder_statuses(ctx)!r}"
    )


def _item_notifications(seen, resource_id):
    """Every ConfigurationItemChangeNotification in *seen* that is about one resource, oldest first."""
    out = []
    for envelope, message in seen:
        if not isinstance(message, dict):
            continue
        if message.get("messageType") != "ConfigurationItemChangeNotification":
            continue
        item = message.get("configurationItem")
        if isinstance(item, dict) and item.get("resourceId") == resource_id:
            out.append((envelope, message))
    return out


CHECK = "config-item-change-notification-diff-names-the-changed-field"
GROUP = "data-plane"
SERVICES = ["config", "sns", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A configuration-item change notification reaches an SQS subscriber of the channel's topic with
    a CREATE diff, then an UPDATE diff naming the changed field with its old and new values, which
    is cross-checked against GetResourceConfigHistory.
    """
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    scenario = "config-ci-change-notification-diff"

    _restore_config_recorder_on_teardown(ctx)
    topic_arn = _create_notification_topic(ctx, scenario, account)
    sink_url, _sink_arn = _subscribe_queue(ctx, topic_arn, scenario)

    _start_recording(ctx, scenario, sns_topic_arn=topic_arn)

    created_at = datetime.datetime.now(datetime.timezone.utc)
    observed_name, observed_url = _create_queue(
        ctx, scenario, attributes={"VisibilityTimeout": _INITIAL_TIMEOUT}
    )

    # --- the discovery notification ---
    seen = _drain_notifications(
        ctx,
        sink_url,
        timeout_s=_NOTIFICATION_BUDGET_S,
        predicate=lambda s: bool(_item_notifications(s, observed_url)),
        description=(
            f"a ConfigurationItemChangeNotification for queue {observed_url!r} on the delivery "
            f"channel's SNS topic"
        ),
    )
    envelope, message = _item_notifications(seen, observed_url)[0]
    assert envelope.get("Type") == "Notification", (
        f"expected an SNS Notification envelope, got Type {envelope.get('Type')!r}"
    )
    assert envelope.get("TopicArn") == topic_arn, (
        f"the notification came from {envelope.get('TopicArn')!r}, not the delivery channel's topic "
        f"{topic_arn!r}"
    )
    assert message.get("messageType") == "ConfigurationItemChangeNotification", (
        f"expected messageType ConfigurationItemChangeNotification, got "
        f"{message.get('messageType')!r}"
    )
    created_notification_time = message.get("notificationCreationTime")
    assert isinstance(created_notification_time, str) and created_notification_time, (
        f"the notification must carry a notificationCreationTime, got "
        f"{created_notification_time!r}"
    )
    stamped = datetime.datetime.fromisoformat(created_notification_time.replace("Z", "+00:00"))
    assert stamped >= created_at - datetime.timedelta(seconds=_CLOCK_SKEW_S), (
        f"notificationCreationTime {stamped.isoformat()} predates the moment this check created the "
        f"queue ({created_at.isoformat()}, +/-{_CLOCK_SKEW_S:.0f}s skew), so it cannot describe it"
    )

    item = message["configurationItem"]
    assert item.get("resourceType") == "AWS::SQS::Queue", (
        f"the notified item describes {item.get('resourceType')!r}, expected AWS::SQS::Queue"
    )
    assert item.get("resourceName") == observed_name, (
        f"the notified item names {item.get('resourceName')!r}, expected {observed_name!r}"
    )
    assert item.get("configurationItemStatus") == "ResourceDiscovered", (
        f"the FIRST item for a queue created under a running recorder must be ResourceDiscovered, got "
        f"{item.get('configurationItemStatus')!r}"
    )
    # Unlike GetResourceConfigHistory, which JSON-encodes `configuration` as a string, the SNS
    # notification embeds it as a native object, so there is nothing to decode here.
    first_config = item["configuration"]
    assert first_config["VisibilityTimeout"] == _INITIAL_TIMEOUT, (
        f"the notified configuration does not describe the live queue: expected VisibilityTimeout "
        f"{_INITIAL_TIMEOUT!r}, got {first_config.get('VisibilityTimeout')!r}"
    )
    first_diff = message["configurationItemDiff"]
    assert first_diff.get("changeType") == "CREATE", (
        f"the discovery notification's configurationItemDiff.changeType must be CREATE, got "
        f"{first_diff.get('changeType')!r} (whole diff: {first_diff!r})"
    )

    # --- change exactly one attribute, out of band, and demand the DIFF ---
    sqs.set_queue_attributes(
        QueueUrl=observed_url, Attributes={"VisibilityTimeout": _CHANGED_TIMEOUT}
    )

    def _has_update(s):
        return any(
            (m.get("configurationItemDiff") or {}).get("changeType") == "UPDATE"
            for _e, m in _item_notifications(s, observed_url)
        )

    seen = _drain_notifications(
        ctx,
        sink_url,
        timeout_s=_NOTIFICATION_BUDGET_S,
        predicate=_has_update,
        description=(
            f"an UPDATE ConfigurationItemChangeNotification for queue {observed_url!r} after its "
            f"VisibilityTimeout changed {_INITIAL_TIMEOUT} -> {_CHANGED_TIMEOUT}"
        ),
        seen=seen,
    )
    update_envelope, update_message = next(
        (e, m)
        for e, m in _item_notifications(seen, observed_url)
        if (m.get("configurationItemDiff") or {}).get("changeType") == "UPDATE"
    )
    assert update_envelope.get("TopicArn") == topic_arn, (
        f"the update notification came from {update_envelope.get('TopicArn')!r}, not {topic_arn!r}"
    )
    update_item = update_message["configurationItem"]
    assert update_item.get("configurationItemStatus") == "OK", (
        f"a CHANGE item's configurationItemStatus must be OK (the discovery item was "
        f"ResourceDiscovered), got {update_item.get('configurationItemStatus')!r}"
    )
    assert update_item["configuration"]["VisibilityTimeout"] == _CHANGED_TIMEOUT, (
        f"the update notification's item still reports the OLD attribute value: expected "
        f"{_CHANGED_TIMEOUT!r}, got "
        f"{update_item['configuration'].get('VisibilityTimeout')!r}"
    )

    changed = update_message["configurationItemDiff"]["changedProperties"]
    # Keys are prefixed (e.g. Configuration.VisibilityTimeout) and other keys such as
    # LastModifiedTimestamp also appear, so match the suffix only.
    named = [k for k in changed if k.endswith("VisibilityTimeout")]
    assert len(named) == 1, (
        f"the diff must name the field that changed exactly once: expected one changedProperties key "
        f"ending in 'VisibilityTimeout', got {sorted(changed)!r}"
    )
    prop = changed[named[0]]
    assert str(prop.get("previousValue")) == _INITIAL_TIMEOUT, (
        f"{named[0]}.previousValue must be the attribute's value BEFORE the change: expected "
        f"{_INITIAL_TIMEOUT!r}, got {prop.get('previousValue')!r}"
    )
    assert str(prop.get("updatedValue")) == _CHANGED_TIMEOUT, (
        f"{named[0]}.updatedValue must be the attribute's value AFTER the change: expected "
        f"{_CHANGED_TIMEOUT!r}, got {prop.get('updatedValue')!r}"
    )
    assert prop.get("changeType") == "UPDATE", (
        f"{named[0]}.changeType must be UPDATE for a modified field, got {prop.get('changeType')!r}"
    )

    # --- independent read at Config: the diff must agree with Config's own recorded history ---
    history = _history_items(ctx, "AWS::SQS::Queue", observed_url)
    recorded = [json.loads(i["configuration"])["VisibilityTimeout"] for i in history]
    assert _INITIAL_TIMEOUT in recorded and _CHANGED_TIMEOUT in recorded, (
        f"GetResourceConfigHistory must hold both the pre- and post-change values the notification "
        f"diffed: expected {_INITIAL_TIMEOUT!r} and {_CHANGED_TIMEOUT!r} among {recorded!r}"
    )
    oldest_first = sorted(history, key=lambda i: i["configurationItemCaptureTime"])
    assert json.loads(oldest_first[0]["configuration"])["VisibilityTimeout"] == str(
        prop.get("previousValue")
    ), (
        f"the diff's previousValue {prop.get('previousValue')!r} does not match the earliest value "
        f"Config recorded for the queue "
        f"({json.loads(oldest_first[0]['configuration']).get('VisibilityTimeout')!r})"
    )


def _restore_config_recorder_on_teardown(ctx) -> None:
    """The Config recorder and delivery channel exist once per account and Region: read them now
    and, in a teardown that runs after the check's own, put back exactly what was there."""
    import time

    from botocore.exceptions import ClientError

    cfg = ctx.client("config")

    def _call(fn):
        deadline = time.monotonic() + 60.0
        while True:
            try:
                return fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() > deadline:
                    raise
                time.sleep(2.0)

    def _recorders():
        found = _call(cfg.describe_configuration_recorders)["ConfigurationRecorders"]
        return [r for r in found if not r.get("servicePrincipal")]

    recorders = _recorders()
    statuses = _call(cfg.describe_configuration_recorder_status)["ConfigurationRecordersStatus"]
    recording = {s["name"] for s in statuses if s.get("recording")}
    channels = _call(cfg.describe_delivery_channels)["DeliveryChannels"]
    fields = ("name", "roleARN", "recordingGroup", "recordingMode")

    def _restore() -> None:
        now = _recorders()
        for r in now:
            _call(lambda n=r["name"]: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        kept = {c["name"] for c in channels}
        for c in _call(cfg.describe_delivery_channels)["DeliveryChannels"]:
            if c["name"] not in kept:
                _call(lambda n=c["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
        kept = {r["name"] for r in recorders}
        for r in now:
            if r["name"] not in kept:
                _call(lambda n=r["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        for r in recorders:
            body = {k: v for k, v in r.items() if k in fields}
            _call(lambda b=body: cfg.put_configuration_recorder(ConfigurationRecorder=b))
        for c in channels:
            _call(lambda c=c: cfg.put_delivery_channel(DeliveryChannel=c))
        for r in recorders:
            if r["name"] in recording:
                _call(lambda n=r["name"]: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
