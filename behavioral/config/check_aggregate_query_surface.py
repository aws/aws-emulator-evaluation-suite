"""aggregate-query-surface."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aggregate-query-surface"
GROUP = 'aggregation'
SERVICES = ['config']


def _error(fn):
    """Call fn() and return its botocore (Error.Code, Error.Message); raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_aggregator_quiet(ctx, name):
    try:
        ctx.client("config").delete_configuration_aggregator(
            ConfigurationAggregatorName=name
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigurationAggregatorException":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s")


def _retry_on(fn, error_codes, *, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in error_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _ensure_recording(ctx):
    """Ensure a RECORDING configuration recorder, reusing an existing one or creating the minimal
    role, recorder and delivery channel; clean up only what was created."""
    config = ctx.client("config")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        recorder_name = recorders[0]["name"]
    else:
        role_name = ctx.unique_name("sim2real-behav-cfgqs-role-")
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
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
            ),
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        role_arn = role["Role"]["Arn"]
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
        )
        # on_cleanup runs LIFO and DeleteRole rejects a role with an attached policy, so
        # delete_role is registered first to run after the detach.
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        ctx.on_cleanup(
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
            )
        )

        recorder_name = "default"

        def _create_recorder():
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )

        _retry_on(_create_recorder, ("InvalidRoleException",), timeout_s=60, interval_s=5)
        ctx.on_cleanup(
            lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

    recorder_status = config.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    )["ConfigurationRecordersStatus"][0]

    if recorder_status.get("recording"):
        return recorder_name

    channels = config.describe_delivery_channels().get("DeliveryChannels", [])
    if channels:
        channel_name = channels[0]["name"]
    else:
        account_id = sts.get_caller_identity()["Account"]
        bucket_name = ctx.unique_name("sim2real-behav-cfgqs-").lower()
        # CreateBucket rejects an explicit LocationConstraint in us-east-1.
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
            )
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
        s3.put_bucket_tagging(
            Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
        )

        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSConfigBucketPermissionsCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                },
                {
                    "Sid": "AWSConfigBucketDelivery",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

        channel_name = "default"
        _retry_on(
            lambda: config.put_delivery_channel(
                DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
            ),
            ("InsufficientDeliveryPolicyException", "NoSuchBucketException"),
            timeout_s=60,
            interval_s=5,
        )
        ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))
    return recorder_name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "identity:standalone", "phase:standalone", "plane:control", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """The aggregate read surface returns well-formed results for unpopulated compliance facets,
    surfaces a freshly created S3 bucket through every resource read, and answers an
    undiscovered identifier with ResourceNotDiscoveredException."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    agg_name = ctx.unique_name("sim2real-behav-cfg-agg-")

    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=agg_name,
        AccountAggregationSources=[{"AccountIds": [account_id], "AllAwsRegions": True}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_aggregator_quiet(ctx, agg_name))

    # The aggregated-source status list is populated asynchronously and may
    # legitimately still be empty; only its shape is contractual here.
    statuses = cfg.describe_configuration_aggregator_sources_status(
        ConfigurationAggregatorName=agg_name
    )["AggregatedSourceStatusList"]
    assert isinstance(statuses, list), (
        f"AggregatedSourceStatusList: expected a list, got {type(statuses).__name__}"
    )

    by_rules = cfg.describe_aggregate_compliance_by_config_rules(
        ConfigurationAggregatorName=agg_name
    )
    assert isinstance(by_rules["AggregateComplianceByConfigRules"], list), (
        "AggregateComplianceByConfigRules is not a list"
    )

    by_packs = cfg.describe_aggregate_compliance_by_conformance_packs(
        ConfigurationAggregatorName=agg_name
    )
    assert isinstance(by_packs["AggregateComplianceByConformancePacks"], list), (
        "AggregateComplianceByConformancePacks is not a list"
    )

    rule_summary = cfg.get_aggregate_config_rule_compliance_summary(
        ConfigurationAggregatorName=agg_name
    )
    assert "AggregateComplianceCounts" in rule_summary, (
        f"AggregateComplianceCounts absent; keys: {sorted(rule_summary)}"
    )

    pack_summary = cfg.get_aggregate_conformance_pack_compliance_summary(
        ConfigurationAggregatorName=agg_name
    )
    assert "AggregateConformancePackComplianceSummaries" in pack_summary, (
        f"AggregateConformancePackComplianceSummaries absent; keys: {sorted(pack_summary)}"
    )

    # Positive control: without a real discovered resource, "well-formed empty" and "always
    # not-found" answers could not be told apart from a target that discovers nothing.
    _ensure_recording(ctx)
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-cfgqs-").lower()
    # CreateBucket rejects an explicit LocationConstraint in us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    real_identifier = {
        "SourceAccountId": account_id,
        "SourceRegion": ctx.region,
        "ResourceId": bucket_name,
        "ResourceType": "AWS::S3::Bucket",
    }

    def _list_bucket_ids():
        return cfg.list_aggregate_discovered_resources(
            ConfigurationAggregatorName=agg_name, ResourceType="AWS::S3::Bucket"
        )["ResourceIdentifiers"]

    discovered_ids = _poll_until(
        _list_bucket_ids,
        lambda ids: any(i["ResourceId"] == bucket_name for i in ids),
        timeout_s=200,
        description="aggregator surfacing the check's bucket via ListAggregateDiscoveredResources",
    )
    assert any(i["ResourceId"] == bucket_name for i in discovered_ids), (
        f"the check's bucket is not among {len(discovered_ids)} discovered identifiers"
    )

    # The counts are indexed on their own schedule, after ListAggregateDiscoveredResources: wait
    # until the bucket's own type is counted, then read the unfiltered total once, which must
    # count at least those buckets.
    bucket_count = _poll_until(
        lambda: cfg.get_aggregate_discovered_resource_counts(
            ConfigurationAggregatorName=agg_name, Filters={"ResourceType": "AWS::S3::Bucket"}
        )["TotalDiscoveredResources"],
        lambda n: n >= 1,
        timeout_s=300,
        description="aggregator counting the check's discovered bucket type",
    )
    res_counts = cfg.get_aggregate_discovered_resource_counts(
        ConfigurationAggregatorName=agg_name
    )
    assert "TotalDiscoveredResources" in res_counts, (
        f"TotalDiscoveredResources absent; keys: {sorted(res_counts)}"
    )
    assert res_counts["TotalDiscoveredResources"] >= bucket_count, (
        f"expected the unfiltered total to count at least the {bucket_count} S3 bucket(s) the "
        f"ResourceType filter counts, got TotalDiscoveredResources={res_counts['TotalDiscoveredResources']}"
    )

    # SelectAggregateResourceConfig reads its own index on its own sync schedule, so it gets
    # its own bounded wait.
    def _select():
        return cfg.select_aggregate_resource_config(
            ConfigurationAggregatorName=agg_name,
            Expression=(
                "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket' "
                f"AND resourceId = '{bucket_name}'"
            ),
        )

    def _select_rows(resp):
        return [json.loads(r) for r in resp["Results"]]

    selected = _poll_until(
        _select,
        lambda resp: any(r.get("resourceId") == bucket_name for r in _select_rows(resp)),
        timeout_s=120,
        description="SelectAggregateResourceConfig surfacing the check's bucket",
    )
    selected_rows = _select_rows(selected)
    assert any(r.get("resourceId") == bucket_name for r in selected_rows), (
        f"the check's bucket is not among {len(selected_rows)} selected rows"
    )

    # GetAggregateResourceConfig reads yet another index and can still answer
    # ResourceNotDiscoveredException for the bucket the Select above surfaced.
    item = _retry_on(
        lambda: cfg.get_aggregate_resource_config(
            ConfigurationAggregatorName=agg_name, ResourceIdentifier=real_identifier
        ),
        ("ResourceNotDiscoveredException",),
        timeout_s=120,
        interval_s=5,
    )["ConfigurationItem"]
    assert item["resourceId"] == bucket_name, "GetAggregateResourceConfig returned another resourceId"
    assert item["resourceType"] == "AWS::S3::Bucket", (
        f"resourceType: expected AWS::S3::Bucket, got {item['resourceType']!r}"
    )

    bogus_identifier = {
        "SourceAccountId": account_id,
        "SourceRegion": ctx.region,
        "ResourceId": "sim2real-behav-nonexistent-bucket",
        "ResourceType": "AWS::S3::Bucket",
    }
    # BatchGetAggregateResourceConfig syncs more slowly than the reads above and can still
    # return the real bucket as Unprocessed, so it gets its own bounded wait.
    def _batch_get():
        return cfg.batch_get_aggregate_resource_config(
            ConfigurationAggregatorName=agg_name,
            ResourceIdentifiers=[bogus_identifier, real_identifier],
        )

    batch = _poll_until(
        _batch_get,
        lambda b: any(i["resourceId"] == bucket_name for i in b["BaseConfigurationItems"]),
        timeout_s=120,
        description="BatchGetAggregateResourceConfig surfacing the check's bucket",
    )
    base_ids = {i["resourceId"] for i in batch["BaseConfigurationItems"]}
    assert base_ids == {bucket_name}, (
        f"BaseConfigurationItems: expected only the check's bucket, got {len(base_ids)} ids"
    )
    unprocessed_ids = {r["ResourceId"] for r in batch["UnprocessedResourceIdentifiers"]}
    assert unprocessed_ids == {"sim2real-behav-nonexistent-bucket"}, (
        f"UnprocessedResourceIdentifiers: expected only the bogus id, got {sorted(unprocessed_ids)}"
    )

    rule_details = cfg.get_aggregate_compliance_details_by_config_rule(
        ConfigurationAggregatorName=agg_name,
        ConfigRuleName="sim2real-behav-no-such-rule",
        AccountId=account_id,
        AwsRegion=ctx.region,
    )
    assert rule_details["AggregateEvaluationResults"] == [], (
        f"AggregateEvaluationResults: expected [], got {len(rule_details['AggregateEvaluationResults'])} results"
    )

    code, message = _error(
        lambda: cfg.get_aggregate_resource_config(
            ConfigurationAggregatorName=agg_name, ResourceIdentifier=bogus_identifier
        )
    )
    assert code == "ResourceNotDiscoveredException", f"unexpected code: {code}"
    assert message == (
        "You have specified a resource that is either unknown or has not been discovered."
    ), message

    pending = cfg.describe_pending_aggregation_requests()
    assert isinstance(pending["PendingAggregationRequests"], list), (
        "PendingAggregationRequests is not a list"
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
