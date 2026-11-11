"""batch-get-aggregate-resource-config-matches-individual-gets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-aggregate-resource-config-matches-individual-gets"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """BatchGetAggregateResourceConfig for two IAM roles a self-aggregator discovered (by RoleId) returns
    both with no unprocessed identifiers, each matching GetAggregateResourceConfig's resourceType, arn,
    accountId and resourceName."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _ensure_recorder_and_channel(ctx)

    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_names = [ctx.unique_name("sim2real-batch-role-a-"), ctx.unique_name("sim2real-batch-role-b-")]
    role_ids = {}
    for name in role_names:
        role = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )["Role"]
        role_ids[name] = role["RoleId"]
        ctx.on_cleanup(lambda n=name: iam.delete_role(RoleName=n))

    agg_name = ctx.unique_name("sim2real-batch-agg-")
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=agg_name,
        AccountAggregationSources=[{"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [ctx.region]}],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=agg_name))

    identifiers = [
        {"SourceAccountId": account_id, "SourceRegion": ctx.region, "ResourceId": role_ids[name], "ResourceType": "AWS::IAM::Role"}
        for name in role_names
    ]

    def _both_discovered():
        found = 0
        for ident in identifiers:
            try:
                config.get_aggregate_resource_config(ConfigurationAggregatorName=agg_name, ResourceIdentifier=ident)
                found += 1
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotDiscoveredException":
                    raise
        return found

    _poll_until(lambda: _both_discovered(), lambda n: n == 2, timeout_s=420, interval_s=15)

    def _get_discovered(ident):
        # the aggregator's answer can still flip back to not-discovered right after both appear
        deadline = time.monotonic() + 120
        while True:
            try:
                return config.get_aggregate_resource_config(ConfigurationAggregatorName=agg_name, ResourceIdentifier=ident)["ConfigurationItem"]
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotDiscoveredException" or time.monotonic() > deadline:
                    raise
            time.sleep(2)

    individual = {role_ids[name]: _get_discovered(ident) for name, ident in zip(role_names, identifiers)}

    batch_resp = config.batch_get_aggregate_resource_config(ConfigurationAggregatorName=agg_name, ResourceIdentifiers=identifiers)
    assert batch_resp["UnprocessedResourceIdentifiers"] == [], (
        f"expected all {len(identifiers)} identifiers processed, got unprocessed={batch_resp['UnprocessedResourceIdentifiers']}"
    )
    batch_items = {item["resourceId"]: item for item in batch_resp["BaseConfigurationItems"]}

    expected_ids = set(role_ids.values())
    assert set(batch_items.keys()) == expected_ids, (
        f"expected batch resourceIds {expected_ids}, got {set(batch_items.keys())}"
    )
    for name in role_names:
        rid = role_ids[name]
        assert batch_items[rid]["resourceType"] == individual[rid]["resourceType"], (
            f"{name}: batch resourceType {batch_items[rid]['resourceType']!r} != individual {individual[rid]['resourceType']!r}"
        )
        assert batch_items[rid]["arn"] == individual[rid]["arn"], (
            f"{name}: batch arn {batch_items[rid]['arn']!r} != individual {individual[rid]['arn']!r}"
        )
        assert batch_items[rid]["accountId"] == individual[rid]["accountId"], (
            f"{name}: batch accountId {batch_items[rid]['accountId']!r} != individual {individual[rid]['accountId']!r}"
        )
        assert batch_items[rid]["resourceName"] == name, (
            f"{name}: batch resourceName {batch_items[rid].get('resourceName')!r} != created role name {name!r}"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _ensure_recorder_and_channel(ctx):
    config = ctx.client("config")
    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        name = recorders[0]["name"]
        status = config.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])["ConfigurationRecordersStatus"][0]
        if not status.get("recording"):
            config.start_configuration_recorder(ConfigurationRecorderName=name)
        return name

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cfg-recorder-role-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"))

    bucket_name = ctx.unique_name("sim2real-cfg-bucket-").lower()
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AWSConfigBucketPermissionsCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket_name}"},
            {"Sid": "AWSConfigBucketExistenceCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket_name}"},
            {"Sid": "AWSConfigBucketDelivery", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*", "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    recorder_name = ctx.unique_name("sim2real-cfg-recorder-")
    deadline = time.monotonic() + 90
    while True:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {
                        "allSupported": False,
                        "resourceTypes": ["AWS::IAM::Role"],
                        # AWS Config rejects an explicit resourceTypes list with
                        # InvalidRecordingGroupException unless recordingStrategy names it,
                        # and rejects it again if includeGlobalResourceTypes (deprecated) is
                        # also set alongside recordingStrategy.
                        "recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"},
                    },
                },
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))

    deadline = time.monotonic() + 90
    while True:
        try:
            config.put_delivery_channel(DeliveryChannel={"name": recorder_name, "s3BucketName": bucket_name})
            break
        except ClientError as e:
            # Same IAM-propagation window as above: the delivery channel setup assumes the
            # recorder role to validate bucket access before the role's policy has propagated.
            if e.response["Error"]["Code"] in ("InsufficientDeliveryPolicyException", "NoSuchBucketException") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=recorder_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))
    return recorder_name


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
