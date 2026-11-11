"""integration-description-empty-vs-absent-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "integration-description-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An integration created with Description omitted reads back without it, and a sibling
    created with Description="" reads back present-but-empty; on an account not entitled to
    zero-ETL integrations, CreateIntegration's specific refusal leaves no integration behind."""
    rs = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket_absent, source_arn_absent = _create_source_bucket(ctx)
    # Positive control: namespace + workgroup provisioning succeeding proves this
    # account and its Redshift Serverless/S3 credentials are otherwise healthy, so a
    # CreateIntegration refusal below cannot be explained by a broken client/account.
    target_arn = _create_target_namespace(ctx)
    _authorize_s3_event_integration(ctx, rs, bucket_absent, source_arn_absent, target_arn, account_id)

    name_absent = ctx.unique_name("sim2realiabs").lower().replace("-", "").replace("_", "")[:60]

    created_absent = _create_integration_or_assert_entitlement_refusal(
        rs, ctx.time_left, IntegrationName=name_absent, SourceArn=source_arn_absent, TargetArn=target_arn
    )
    if created_absent is None:
        # The refusal itself was already asserted (code + message) inside the helper.
        # Effect-absent via an independent read: no integration object under this name.
        listed = rs.describe_integrations()["Integrations"]
        assert not any(i["IntegrationName"] == name_absent for i in listed), (
            "a denied CreateIntegration must not leave an integration object behind"
        )
        return

    ctx.on_cleanup(lambda: _delete_integration(rs, created_absent["IntegrationArn"]))
    assert "Description" not in created_absent, f"expected no Description key, got {created_absent.get('Description')!r}"

    # Account is entitled -- exercise the full empty-vs-absent representation contract.
    # Real AWS permits only one integration per (source, target) pair, so the "empty"
    # sibling needs its own source bucket even though it shares the same target.
    bucket_empty, source_arn_empty = _create_source_bucket(ctx)
    _authorize_s3_event_integration(ctx, rs, bucket_empty, source_arn_empty, target_arn, account_id)
    name_empty = ctx.unique_name("sim2realiemp").lower().replace("-", "").replace("_", "")[:60]

    created_empty = _create_integration_or_assert_entitlement_refusal(
        rs, ctx.time_left, IntegrationName=name_empty, SourceArn=source_arn_empty, TargetArn=target_arn, Description=""
    )
    assert created_empty is not None, "entitlement was already proven present by the first create"
    ctx.on_cleanup(lambda: _delete_integration(rs, created_empty["IntegrationArn"]))
    assert created_empty.get("Description") == "", f"expected empty-string Description, got {created_empty.get('Description')!r}"

    described_absent = rs.describe_integrations(IntegrationArn=created_absent["IntegrationArn"])["Integrations"][0]
    described_empty = rs.describe_integrations(IntegrationArn=created_empty["IntegrationArn"])["Integrations"][0]

    assert "Description" not in described_absent, f"absent Description resurfaced as {described_absent.get('Description')!r}"
    assert described_empty.get("Description") == "", f"empty Description drifted to {described_empty.get('Description')!r}"


# ===== helpers =====

def _create_source_bucket(ctx: Any) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-integ-src-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket, f"arn:aws:s3:::{bucket}"


def _authorize_s3_event_integration(ctx: Any, rs: Any, bucket: str, source_arn: str, target_arn: str, account_id: str) -> None:
    """Wire up the prerequisites documented for an S3 event integration: a
    bucket policy letting the redshift service read/write bucket notification
    config for integrations from this account, and a namespace resource
    policy authorizing both the service (AuthorizeInboundIntegration) and this
    caller (CreateInboundIntegration) to build an inbound integration from
    this specific bucket.
    """
    s3 = ctx.client("s3")
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAutoCopyPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["s3:GetBucketNotification", "s3:PutBucketNotification", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:aws:redshift:{ctx.region}:{account_id}:integration:*"},
                    "StringEquals": {"aws:SourceAccount": account_id},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    # The caller's own principal (an STS assumed-role session ARN in this harness) is not
    # a stable match for a resource-policy Principal -- account root is, and is what grants
    # CreateInboundIntegration to whichever principal in this account actually calls it.
    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": target_arn,
                "Condition": {
                    "StringEquals": {"aws:SourceArn": source_arn, "aws:SourceAccount": account_id}
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": target_arn,
                "Condition": {
                    "StringEquals": {"aws:SourceArn": source_arn, "aws:SourceAccount": account_id}
                },
            },
        ],
    }
    rs.put_resource_policy(ResourceArn=target_arn, Policy=json.dumps(resource_policy))
    ctx.on_cleanup(lambda: _delete_resource_policy(rs, target_arn))


def _create_integration_or_assert_entitlement_refusal(rs: Any, time_left: Any, **kwargs: Any) -> dict | None:
    """Create a zero-ETL/S3-event integration, retrying every 2 s for up to 120 s through the
    resource-policy propagation and "not active" errors. A non-entitled account's permanent
    "You don't have access to zero-ETL integrations" refusal returns None; anything else raises."""
    import time as _time

    from botocore.exceptions import ClientError

    left = time_left()
    deadline = _time.monotonic() + (120.0 if left is None else min(120.0, left))
    last_err: ClientError | None = None
    while True:
        try:
            return rs.create_integration(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err.response["Error"].get("Message", ""))
            transient = (code == "InvalidParameterValue" and "doesn't exist or you don't have" in msg) or (
                # IntegrationConflictOperationFault's own message says to wait and retry --
                # the workgroup reaching status AVAILABLE does not mean the underlying data
                # warehouse has finished becoming "active" for integration purposes yet.
                code == "IntegrationConflictOperationFault" and "not active" in msg
            )
            if not transient:
                raise
            last_err = err
        if _time.monotonic() >= deadline:
            break
        _time.sleep(2)
    code = last_err.response["Error"]["Code"]
    msg = str(last_err.response["Error"].get("Message", ""))
    if code == "InvalidParameterValue" and "You don't have access to zero-ETL integrations" in msg:
        # The specific, permanent account-entitlement refusal -- the observable contract
        # for a non-entitled account, not an unresolved transient condition.
        return None
    raise last_err


def _delete_resource_policy(rs: Any, resource_arn: str) -> None:
    try:
        rs.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _delete_bucket(s3: Any, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_target_namespace(ctx: Any) -> str:
    rss = ctx.client("redshift-serverless")
    name = ctx.unique_name("sim2real-integ-ns-").lower().replace("_", "-")
    resp = rss.create_namespace(namespaceName=name)
    ctx.on_cleanup(lambda: _delete_namespace(rss, name))
    _poll_until(
        probe=lambda: rss.get_namespace(namespaceName=name)["namespace"]["status"],
        predicate=lambda s: s == "AVAILABLE",
        timeout_s=60,
        interval_s=3,
    )
    # CreateIntegration validates the target against a real, queryable data
    # warehouse -- a bare namespace with no compute attached is not resolvable
    # as an integration target (IntegrationTargetNotFoundFault). Attach a
    # minimal workgroup to the namespace so the namespace is a complete,
    # addressable data warehouse.
    _create_workgroup_for_namespace(ctx, rss, name)
    return resp["namespace"]["namespaceArn"]


def _create_workgroup_for_namespace(ctx: Any, rss: Any, namespace_name: str) -> None:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets][:3]
    if len(subnet_ids) < 3:
        raise AssertionError(f"Redshift Serverless needs 3 subnets; the run's shared network has {subnet_ids}")
    workgroup_name = ctx.unique_name("sim2real-integ-wg-").lower().replace("_", "-")
    rss.create_workgroup(
        workgroupName=workgroup_name,
        namespaceName=namespace_name,
        baseCapacity=8,
        subnetIds=subnet_ids,
        configParameters=[{"parameterKey": "enable_case_sensitive_identifier", "parameterValue": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_workgroup(rss, workgroup_name))
    _poll_until(
        probe=lambda: rss.get_workgroup(workgroupName=workgroup_name)["workgroup"]["status"],
        predicate=lambda s: s == "AVAILABLE",
        timeout_s=600,
        interval_s=10,
    )


def _delete_workgroup(rss: Any, workgroup_name: str) -> None:
    _delete_retrying(
        lambda: rss.delete_workgroup(workgroupName=workgroup_name),
        "ResourceNotFoundException", "ConflictException", "operation running on the workgroup",
    )


def _delete_namespace(rss: Any, name: str) -> None:
    _delete_retrying(
        lambda: rss.delete_namespace(namespaceName=name),
        "ResourceNotFoundException", "ConflictException", "Delete the associated workgroup",
    )


def _delete_integration(rs: Any, integration_arn: str) -> None:
    _delete_retrying(
        lambda: rs.delete_integration(IntegrationArn=integration_arn),
        "IntegrationNotFoundFault", "IntegrationConflictOperationFault", "not active",
    )


def _delete_retrying(delete: Any, not_found: str, busy_code: str, busy_text: str, timeout_s: float = 420.0) -> None:
    """Teardown delete: absent is done; the refusal AWS gives while the warehouse or a dependent
    is still settling is retried every 2 s to the deadline; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == not_found:
                return
            if code != busy_code or busy_text not in str(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
