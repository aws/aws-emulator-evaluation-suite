"""config-managed-policy-item-relates-to-the-roles-it-is-attached-to."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_CI_BUDGET_S = 600.0
_SECOND_CI_BUDGET_S = 600.0

# Global IAM types are recorded only in Regions where Config was available before February 2022.
_GLOBAL_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": True}

#: The relationship wording AWS documents for a managed policy attached to a role.
_ATTACHED_TO_ROLE = "Is attached to Role"

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition", ctx=None):
    """A bounded retry with a stated reason that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    # freshly created role has propagated, and IAM exposes no signal that a role has become
    # assumable, so this bounded retry is what makes the check correct.
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    last = None
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
            if code not in ("InsufficientPermissionsException", "AccessDeniedException"):
                raise
            last = exc
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"recorder {name!r} accepted: the run budget ended first; not graded") from None
                raise last
            time.sleep(2)


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
        timeout_s=_budget_s(ctx, _TRANSITION_BUDGET_S),
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
        ctx=ctx,
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=_budget_s(ctx, _TRANSITION_BUDGET_S),
        interval_s=2,
        description=f"recorder {name!r} reports recording=False",
        ctx=ctx,
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
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while True:
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
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"delivery channel {name!r} accepted: the run budget ended first; not graded") from None
                raise last
            time.sleep(2)


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
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _history_items(ctx, resource_type, resource_id)
        if predicate(last):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


_PROBE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_PROBE_PERMISSION_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "config:DescribeConfigRules", "Resource": "*"}
        ],
    }
)


def _delete_probe_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_probe_role(ctx, prefix, scenario):
    """A role this check owns and will delete. Returns (name, role_id)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_PROBE_TRUST_POLICY,
        Description=f"sim2real behavioral fidelity probe role ({scenario})",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_probe_role(ctx, name))
    return name, role["RoleId"]


def _create_probe_policy(ctx, scenario):
    """A customer-managed policy this check owns. Returns (name, arn, policy_id)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cfg-policy-")
    policy = iam.create_policy(
        PolicyName=name,
        PolicyDocument=_PROBE_PERMISSION_POLICY,
        Description="sim2real behavioral fidelity probe policy for AWS Config relationships",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["Policy"]

    def _teardown():
        iam2 = ctx.client("iam")
        try:
            for page in iam2.get_paginator("list_entities_for_policy").paginate(
                PolicyArn=policy["Arn"], EntityFilter="Role"
            ):
                for role in page.get("PolicyRoles", []):
                    try:
                        iam2.detach_role_policy(
                            RoleName=role["RoleName"], PolicyArn=policy["Arn"]
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "NoSuchEntity":
                            raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam2.delete_policy(PolicyArn=policy["Arn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return name, policy["Arn"], policy["PolicyId"]


def _role_relationships(item):
    return [
        r for r in item["relationships"] if r.get("resourceType") == "AWS::IAM::Role"
    ]


CHECK = "config-managed-policy-item-relates-to-the-roles-it-is-attached-to"
GROUP = "resource-config"
SERVICES = ["config", "iam"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A managed policy's configuration item relates to exactly the roles it is attached to: one
    attachment gives attachmentCount 1 and one Role relationship with that RoleId; a second gives
    attachmentCount 2 and both RoleIds, also through BatchGetResourceConfig.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    scenario = "config-policy-role-relationships"

    _start_recording(ctx, scenario, recording_group=dict(_GLOBAL_RECORDING_GROUP))

    policy_name, policy_arn, policy_id = _create_probe_policy(ctx, scenario)
    attached_name, attached_id = _create_probe_role(ctx, "sim2real-behav-cfg-attached-", scenario)
    bystander_name, bystander_id = _create_probe_role(
        ctx, "sim2real-behav-cfg-bystander-", scenario
    )
    assert attached_id != bystander_id, (
        f"the two probe roles must be distinct: both reported RoleId {attached_id!r}"
    )

    iam.attach_role_policy(RoleName=attached_name, PolicyArn=policy_arn)
    live = {
        r["RoleName"]
        for page in iam.get_paginator("list_entities_for_policy").paginate(
            PolicyArn=policy_arn, EntityFilter="Role"
        )
        for r in page.get("PolicyRoles", [])
    }
    assert live == {attached_name}, (
        f"IAM must report the policy attached to exactly one role before Config is asked: expected "
        f"{{{attached_name!r}}}, got {sorted(live)!r}"
    )

    # --- one attachment: one relationship, and it names the right role ---
    items = _await_history_items(
        ctx,
        "AWS::IAM::Policy",
        policy_id,
        predicate=lambda its: any(
            json.loads(i["configuration"]).get("attachmentCount") == 1 for i in its
        ),
        timeout_s=_CI_BUDGET_S,
        description=(
            f"a configuration item for managed policy {policy_name!r} ({policy_id!r}) reporting "
            f"attachmentCount 1"
        ),
    )
    single = next(i for i in items if json.loads(i["configuration"]).get("attachmentCount") == 1)
    config_blob = json.loads(single["configuration"])
    assert config_blob.get("policyName") == policy_name, (
        f"the recorded configuration describes policy {config_blob.get('policyName')!r}, expected "
        f"{policy_name!r}"
    )
    assert single["arn"] == policy_arn, (
        f"the item's arn {single['arn']!r} != the live policy arn {policy_arn!r}"
    )
    related = _role_relationships(single)
    assert len(related) == 1, (
        f"a policy attached to exactly one role must carry exactly one AWS::IAM::Role relationship, "
        f"got {related!r} (full relationships: {single['relationships']!r})"
    )
    assert related[0].get("resourceId") == attached_id, (
        f"the relationship names role {related[0].get('resourceId')!r}, expected the RoleId of the "
        f"role the policy is attached to ({attached_id!r} / {attached_name!r})"
    )
    assert related[0].get("resourceName") == attached_name, (
        f"the relationship's resourceName is {related[0].get('resourceName')!r}, expected "
        f"{attached_name!r}"
    )
    assert related[0].get("relationshipName") == _ATTACHED_TO_ROLE, (
        f"expected relationshipName {_ATTACHED_TO_ROLE!r}, got "
        f"{related[0].get('relationshipName')!r}"
    )
    assert bystander_id not in [r.get("resourceId") for r in single["relationships"]], (
        f"the unattached role {bystander_name!r} ({bystander_id!r}) appears in the policy's "
        f"relationships: {single['relationships']!r} - a target that relates every co-existing "
        f"resource fails here"
    )
    assert len(related) == config_blob.get("attachmentCount"), (
        f"the item's own attachmentCount ({config_blob.get('attachmentCount')!r}) disagrees with the "
        f"number of role relationships it carries ({len(related)})"
    )

    # --- a second attachment must move BOTH the counter and the graph ---
    # The first item was captured before it was read; passing a second boundary first keeps a
    # second-resolution capture time of the next item strictly later.
    time.sleep(1.1)
    iam.attach_role_policy(RoleName=bystander_name, PolicyArn=policy_arn)
    grown = _await_history_items(
        ctx,
        "AWS::IAM::Policy",
        policy_id,
        predicate=lambda its: any(
            json.loads(i["configuration"]).get("attachmentCount") == 2 for i in its
        ),
        timeout_s=_SECOND_CI_BUDGET_S,
        description=(
            f"a configuration item for policy {policy_name!r} reporting attachmentCount 2 after the "
            f"second AttachRolePolicy"
        ),
    )
    both_item = next(
        i for i in grown if json.loads(i["configuration"]).get("attachmentCount") == 2
    )
    both_related = _role_relationships(both_item)
    assert {r.get("resourceId") for r in both_related} == {attached_id, bystander_id}, (
        f"after two attachments the policy must relate to both RoleIds: expected "
        f"{sorted([attached_id, bystander_id])!r}, got "
        f"{sorted(r.get('resourceId') for r in both_related)!r}"
    )
    assert len(both_related) == json.loads(both_item["configuration"]).get("attachmentCount"), (
        f"attachmentCount {json.loads(both_item['configuration']).get('attachmentCount')!r} "
        f"disagrees with the {len(both_related)} role relationships in the same item"
    )
    assert all(r.get("relationshipName") == _ATTACHED_TO_ROLE for r in both_related), (
        f"every role attachment must be described the same way: got "
        f"{[r.get('relationshipName') for r in both_related]!r}"
    )
    assert both_item["configurationItemCaptureTime"] > single["configurationItemCaptureTime"], (
        f"the two-attachment item was captured at {both_item['configurationItemCaptureTime']!r}, "
        f"which is not after the one-attachment item's "
        f"{single['configurationItemCaptureTime']!r} - so it is not a new recording"
    )

    # --- the same graph through a different read operation ---
    base = cfg.batch_get_resource_config(
        resourceKeys=[{"resourceType": "AWS::IAM::Policy", "resourceId": policy_id}]
    )["baseConfigurationItems"]
    assert [i["resourceId"] for i in base] == [policy_id], (
        f"BatchGetResourceConfig must return exactly the recorded policy, got "
        f"{[i.get('resourceId') for i in base]!r}"
    )
    assert json.loads(base[0]["configuration"]).get("attachmentCount") == 2, (
        f"the other read path reports attachmentCount "
        f"{json.loads(base[0]['configuration']).get('attachmentCount')!r}, expected 2"
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
