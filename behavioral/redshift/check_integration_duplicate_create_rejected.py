"""integration-duplicate-create-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "integration-duplicate-create-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a zero-ETL Integration under a name already in use is rejected with
    IntegrationAlreadyExistsFault and creates no second object under that name, while a
    differently-named integration from a distinct source to the same target succeeds."""
    redshift = ctx.client("redshift")
    s3 = ctx.client("s3")
    rss = ctx.client("redshift-serverless")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-integ-src-")
    _create_bucket(ctx, s3, bucket_name)
    source_arn = f"arn:aws:s3:::{bucket_name}"

    bucket_name2 = ctx.unique_name("sim2real-integ-src2-")
    _create_bucket(ctx, s3, bucket_name2)
    source_arn2 = f"arn:aws:s3:::{bucket_name2}"

    # The source S3 bucket must carry a bucket policy that authorizes the Redshift service
    # principal to manage bucket notifications for any integration in this account/region, or
    # CreateIntegration is rejected with InvalidParameterValue ("...doesn't have a bucket
    # policy that allows the correct permissions") before reaching name-uniqueness validation.
    import json

    def _bucket_policy(bname):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Auto-Copy-Policy-01",
                    "Effect": "Allow",
                    "Principal": {"Service": "redshift.amazonaws.com"},
                    "Action": [
                        "s3:GetBucketNotification",
                        "s3:PutBucketNotification",
                        "s3:GetBucketLocation",
                    ],
                    "Resource": f"arn:aws:s3:::{bname}",
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:redshift:{ctx.region}:{account_id}:integration:*"
                        },
                        "StringEquals": {"aws:SourceAccount": account_id},
                    },
                }
            ],
        }

    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(_bucket_policy(bucket_name)))
    s3.put_bucket_policy(Bucket=bucket_name2, Policy=json.dumps(_bucket_policy(bucket_name2)))

    namespace_name = ctx.unique_name("sim2real-integ-ns-")
    ns = rss.create_namespace(namespaceName=namespace_name)["namespace"]
    ctx.on_cleanup(lambda: _delete_namespace(rss, namespace_name))
    target_arn = ns["namespaceArn"]

    # A zero-ETL integration target must be a fully provisioned, available data warehouse --
    # a bare namespace with no workgroup is not resolvable as an integration target and yields
    # IntegrationTargetNotFoundFault. Create a minimal workgroup bound to the namespace and wait
    # for it to leave the creating state.
    workgroup_name = ctx.unique_name("sim2real-integ-wg-")
    rss.create_workgroup(
        workgroupName=workgroup_name,
        namespaceName=namespace_name,
        baseCapacity=8,
        subnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_workgroup(rss, workgroup_name))
    _wait_for_workgroup_available(rss, workgroup_name)

    # The target warehouse must have case-sensitive identifiers enabled for zero-ETL
    # integrations to be created against it.
    rss.update_workgroup(
        workgroupName=workgroup_name,
        configParameters=[{"parameterKey": "enable_case_sensitive_identifier", "parameterValue": "true"}],
    )
    _wait_for_workgroup_available(rss, workgroup_name)


    # The target data warehouse must carry a resource policy authorizing each source ARN and
    # this account's principal to create an inbound integration, or CreateIntegration is
    # rejected with InvalidParameterValue ("...doesn't exist or you don't have the required
    # permissions") before it ever reaches name-uniqueness validation. A distinct positive
    # control below needs its own source, so both source ARNs are authorized up front (only
    # one integration is permitted per source/target pair, so re-using the same source ARN for
    # the "different integration" positive control would itself be rejected as a duplicate).
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": target_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": [source_arn, source_arn2],
                        "aws:SourceAccount": account_id,
                    }
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": target_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": [source_arn, source_arn2],
                        "aws:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    redshift.put_resource_policy(ResourceArn=target_arn, Policy=json.dumps(policy))
    ctx.on_cleanup(lambda: _delete_resource_policy(redshift, target_arn))


    name1 = ctx.unique_name("sim2real-integ-a-")
    first = _create_integration_with_retry(ctx, redshift, source_arn, target_arn, name1)
    arn1 = first["IntegrationArn"]
    ctx.on_cleanup(lambda: _delete_integration(redshift, arn1))
    _wait_for_integration_active(redshift, arn1)

    code, message = _error(
        lambda: redshift.create_integration(
            SourceArn=source_arn, TargetArn=target_arn, IntegrationName=name1
        )
    )
    assert code == "IntegrationAlreadyExistsFault", code
    assert message == (
        f"A zero-ETL integration named {name1} already exists in account {account_id}. "
        "Integration names must be unique within an account. Specify a different name for your "
        "integration, or delete the existing integration."
    ), f"unexpected IntegrationAlreadyExistsFault message {message!r}"

    # effect absent: exactly one integration named name1 exists.
    described = redshift.describe_integrations(IntegrationArn=arn1)["Integrations"]
    assert len(described) == 1
    assert described[0]["IntegrationArn"] == arn1
    assert described[0]["IntegrationName"] == name1

    # positive control: a differently-named integration against a distinct source (same
    # target) succeeds -- proving the rejection above is specific to the duplicate
    # source/target pairing, not a broken client/credentials/target. Only one create/modify
    # operation may be in flight against a given target at a time, so wait for the first
    # integration to leave its transitional "creating" state first.
    name2 = ctx.unique_name("sim2real-integ-b-")
    second = _create_integration_with_retry(ctx, redshift, source_arn2, target_arn, name2)
    arn2 = second["IntegrationArn"]
    ctx.on_cleanup(lambda: _delete_integration(redshift, arn2))
    assert arn2 != arn1

    # independent read at the destination: the positive control's own create response is not
    # the verdict -- confirm the second integration is actually visible via DescribeIntegrations,
    # distinct from and alongside the first.
    described_all = redshift.describe_integrations()["Integrations"]
    by_arn = {i["IntegrationArn"]: i for i in described_all}
    assert arn2 in by_arn, f"{arn2} not visible via DescribeIntegrations after create"
    assert by_arn[arn2]["IntegrationName"] == name2
    assert arn1 in by_arn, f"{arn1} unexpectedly absent after the positive control"




# ===== helpers =====
def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises, so an
    accepted call is reported as such and not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_integration_with_retry(ctx, redshift, source_arn, target_arn, name):
    """Resource-policy propagation into the integration authorization path can lag after
    PutResourcePolicy returns; retry the create on the specific permission error every 2 s
    for up to 60 s."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            return redshift.create_integration(
                SourceArn=source_arn, TargetArn=target_arn, IntegrationName=name
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err.response["Error"].get("Message", ""))
            if not (code == "InvalidParameterValue" and (
                "doesn't exist or you don't have" in msg
                or "doesn't have a bucket policy" in msg
                or "resource policy" in msg.lower()
            )) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_for_integration_active(redshift, arn, timeout_s=900):
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            described = redshift.describe_integrations(IntegrationArn=arn)["Integrations"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "IntegrationNotFoundFault":
                time.sleep(5)
                continue
            raise
        if described:
            status = described[0]["Status"]
            if status == "active":
                return described[0]
            if status in ("failed", "deletion_failed"):
                raise AssertionError(f"integration {arn} entered unexpected status {status}")
        time.sleep(2)
    raise AssertionError(f"integration {arn} did not become active within {timeout_s}s")


def _delete_resource_policy(redshift, resource_arn):
    from botocore.exceptions import ClientError

    try:
        redshift.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundFault",):
            raise


def _wait_for_workgroup_available(rss, workgroup_name, timeout_s=600):
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            wg = rss.get_workgroup(workgroupName=workgroup_name)["workgroup"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(5)
                continue
            raise
        status = wg["status"]
        if status == "AVAILABLE":
            return wg
        if status in ("FAILED", "DELETING"):
            raise AssertionError(f"workgroup {workgroup_name} entered unexpected status {status}")
        time.sleep(2)
    raise AssertionError(f"workgroup {workgroup_name} did not become AVAILABLE within {timeout_s}s")


def _delete_workgroup(rss, workgroup_name):
    """Delete the workgroup and wait until it is gone. DeleteWorkgroup answers ConflictException
    while an integration teardown is still running against it, so retry through that."""
    from botocore.exceptions import ClientError

    deadline = time.time() + 1500
    while time.time() < deadline:
        try:
            status = rss.get_workgroup(workgroupName=workgroup_name)["workgroup"]["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status != "DELETING":
            try:
                rss.delete_workgroup(workgroupName=workgroup_name)
            except ClientError as err:
                if err.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
                    raise
        time.sleep(15)
    raise AssertionError(f"workgroup {workgroup_name} was not deleted within 1500s")


def _delete_namespace(rss, namespace_name):
    """Delete the namespace once its workgroup is gone; retry ConflictException and wait for it to vanish."""
    from botocore.exceptions import ClientError

    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            status = rss.get_namespace(namespaceName=namespace_name)["namespace"]["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status != "DELETING":
            try:
                rss.delete_namespace(namespaceName=namespace_name)
            except ClientError as err:
                if err.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
                    raise
        time.sleep(15)
    raise AssertionError(f"namespace {namespace_name} was not deleted within 900s")



def _create_bucket(ctx, s3, bucket_name):
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))


def _delete_integration(redshift, arn):
    """Delete the integration and wait until DescribeIntegrations no longer finds it, so the
    workgroup teardown that follows does not collide with the integration teardown."""
    from botocore.exceptions import ClientError

    deadline = time.time() + 1200
    while time.time() < deadline:
        try:
            redshift.delete_integration(IntegrationArn=arn)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "IntegrationNotFoundFault":
                return
            if code in ("IntegrationConflictOperationFault", "IntegrationConflictStateFault"):
                time.sleep(10)
                continue
            raise
    while time.time() < deadline:
        try:
            redshift.describe_integrations(IntegrationArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "IntegrationNotFoundFault":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"could not delete integration {arn} within 1200s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
