"""integration-conflict-and-quota-errors."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-conflict-and-quota-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]

MSG_CONFLICT = (
    "Unable to perform create operation on the specified zero-ETL integration because its target "
    "Redshift data warehouse is not active. Wait until the data warehouse is active and try again."
)
MSG_ALREADY_EXISTS = (
    "An integration from source {source} to target {target} already exists. "
    "Only one integration is allowed."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIntegration is IntegrationConflictOperationFault while the target workgroup provisions,
    IntegrationAlreadyExistsFault for a duplicate once active, and succeeds again after deletion.
    """
    s3 = ctx.client("s3")
    redshift_serverless = ctx.client("redshift-serverless")
    redshift = ctx.client("redshift")

    import json

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-behav-rsintg-").lower().replace("_", "-")
    # us-east-1 is S3's default region: CreateBucket rejects an explicit
    # LocationConstraint there but requires one everywhere else.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-behavioral", "Value": CHECK}]}
    )
    source_arn = f"arn:aws:s3:::{bucket_name}"

    # The source bucket must allow the Redshift service to inspect/subscribe its event
    # notifications for any integration created against it.
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Sim2RealAutoCopyPolicy",
                        "Effect": "Allow",
                        "Principal": {"Service": "redshift.amazonaws.com"},
                        "Action": [
                            "s3:GetBucketNotification",
                            "s3:PutBucketNotification",
                            "s3:GetBucketLocation",
                        ],
                        "Resource": source_arn,
                        "Condition": {
                            "ArnLike": {
                                "aws:SourceArn": f"arn:aws:redshift:{ctx.region}:{account_id}:integration:*"
                            },
                            "StringEquals": {"aws:SourceAccount": account_id},
                        },
                    }
                ],
            }
        ),
    )

    ns_name = ctx.unique_name("sim2real-behav-rsintgns-").lower().replace("_", "-")
    namespace = redshift_serverless.create_namespace(
        namespaceName=ns_name, tags=[{"key": "sim2real-behavioral", "value": CHECK}]
    )["namespace"]
    ctx.on_cleanup(
        lambda: _quiet_not_found(lambda: _delete_namespace(redshift_serverless, ns_name))
    )
    target_arn = namespace["namespaceArn"]
    redshift_target_arn = target_arn
    _wait_namespace_available(redshift_serverless, ns_name, timeout_s=_budget_s(ctx, 120.0), ctx=ctx)

    # A namespace with no workgroup is not an integration target (IntegrationTargetNotFoundFault),
    # so give it a minimal workgroup in a VPC this check creates.
    ec2 = ctx.client("ec2")
    subnet_ids, delete_network = _create_network(ctx, ec2)

    # The target namespace must have a resource policy authorizing the Redshift service to
    # accept inbound integrations from this bucket, and authorizing this caller to create them.
    redshift.put_resource_policy(
        ResourceArn=redshift_target_arn,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "redshift.amazonaws.com"},
                        "Action": "redshift:AuthorizeInboundIntegration",
                        "Resource": redshift_target_arn,
                        "Condition": {
                            "StringEquals": {
                                "aws:SourceArn": source_arn,
                                "aws:SourceAccount": account_id,
                            }
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "redshift:CreateInboundIntegration",
                        "Resource": redshift_target_arn,
                        "Condition": {
                            "StringEquals": {
                                "aws:SourceArn": source_arn,
                                "aws:SourceAccount": account_id,
                            }
                        },
                    },
                ],
            }
        ),
    )

    wg_name = ctx.unique_name("sim2real-behav-rsintgwg-").lower().replace("_", "-")
    redshift_serverless.create_workgroup(
        workgroupName=wg_name,
        namespaceName=ns_name,
        subnetIds=subnet_ids,
        tags=[{"key": "sim2real-behavioral", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_warehouse_and_wait(redshift_serverless, wg_name, ns_name))
    ctx.on_cleanup(lambda: _quiet_not_found(lambda: redshift.delete_resource_policy(ResourceArn=redshift_target_arn)))

    created_integration_arns: list[str] = []

    def _cleanup_integrations() -> None:
        for arn in created_integration_arns:
            try:
                _delete_integration(redshift, arn, timeout_s=600.0)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "IntegrationNotFoundFault":
                    raise
            _wait_integration_deleted(redshift, arn, timeout_s=600.0)

    ctx.on_cleanup(_cleanup_integrations)

    name_a = ctx.unique_name("sim2realbehava").replace("-", "")

    # Right after creation the workgroup is still provisioning, so the create, issued as the next
    # call after CreateWorkgroup, conflicts with the not-yet-active target warehouse.
    code, message = _refusal(
        lambda: redshift.create_integration(
            IntegrationName=name_a,
            SourceArn=source_arn,
            TargetArn=target_arn,
            TagList=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        )
    )
    assert code == "IntegrationConflictOperationFault", f"expected ConflictOperation, got {code}"
    assert message == MSG_CONFLICT, f"expected {MSG_CONFLICT!r}, got {message!r}"
    assert not any(
        i["IntegrationArn"] for i in redshift.describe_integrations().get("Integrations", [])
        if i.get("IntegrationName") == name_a
    ), "conflicting create must not have created an integration"

    # Once the workgroup is AVAILABLE, the identical create succeeds.
    _wait_workgroup_available(redshift_serverless, wg_name, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)
    resp = _create_integration_with_retry(
        redshift,
        IntegrationName=name_a,
        SourceArn=source_arn,
        TargetArn=target_arn,
        TagList=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        timeout_s=_budget_s(ctx, 240.0),
        ctx=ctx,
    )
    arn_a = resp["IntegrationArn"]
    created_integration_arns.append(arn_a)
    assert resp["Status"] == "creating", resp["Status"]

    # Once the integration is "active", a second create for the same pair is AlreadyExists.
    _wait_integration_active(redshift, arn_a, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    name_b = ctx.unique_name("sim2realbehavb").replace("-", "")
    code, message = _refusal(
        lambda: redshift.create_integration(
            IntegrationName=name_b,
            SourceArn=source_arn,
            TargetArn=target_arn,
            TagList=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        )
    )
    assert code == "IntegrationAlreadyExistsFault", f"expected AlreadyExists, got {code}"
    expected = MSG_ALREADY_EXISTS.format(source=source_arn, target=target_arn)
    assert message == expected, f"expected {expected!r}, got {message!r}"
    still_only_a = [
        i for i in redshift.describe_integrations()["Integrations"] if i["IntegrationArn"] == arn_a
    ]
    assert len(still_only_a) == 1, "duplicate create must not have mutated the existing integration"

    # Positive control: once the first integration is deleted, the same pair can be recreated.
    _delete_integration(redshift, arn_a, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    _wait_integration_deleted(redshift, arn_a, timeout_s=_budget_s(ctx, 180.0), ctx=ctx)
    name_c = ctx.unique_name("sim2realbehavc").replace("-", "")
    resp_c = _create_integration_with_retry(
        redshift,
        IntegrationName=name_c,
        SourceArn=source_arn,
        TargetArn=target_arn,
        TagList=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        timeout_s=_budget_s(ctx, 240.0),
        ctx=ctx,
    )
    arn_c = resp_c["IntegrationArn"]
    created_integration_arns.append(arn_c)
    assert resp_c["Status"] == "creating", resp_c["Status"]

    final = [
        i for i in redshift.describe_integrations()["Integrations"] if i["IntegrationArn"] == arn_c
    ]
    assert len(final) == 1, "recreated integration must be visible via an independent describe"
    assert final[0]["IntegrationName"] == name_c
    _wait_integration_active(redshift, arn_c, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)

    # The workgroup's network interfaces outlive the teardown budget, so the check removes
    # what it built here, in dependency order; the registered cleanups repeat it.
    _delete_integration(redshift, arn_c, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    _wait_integration_deleted(redshift, arn_c, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    _quiet_not_found(lambda: redshift.delete_resource_policy(ResourceArn=redshift_target_arn))
    redshift_serverless.delete_workgroup(workgroupName=wg_name)
    _wait_gone(lambda: redshift_serverless.get_workgroup(workgroupName=wg_name), f"workgroup {wg_name}", timeout_s=_budget_s(ctx, 900.0), ctx=ctx)
    _delete_namespace(redshift_serverless, ns_name)
    _wait_gone(lambda: redshift_serverless.get_namespace(namespaceName=ns_name), f"namespace {ns_name}", timeout_s=_budget_s(ctx, 900.0), ctx=ctx)
    delete_network(wait_s=_budget_s(ctx, 900.0), run_ctx=ctx)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _refusal(fn):
    """Call fn(); return its botocore error ``(code, message)``. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_NOT_FOUND = (
    "ResourceNotFoundException",
    "ResourceNotFoundFault",
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
)


def _quiet_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _NOT_FOUND:
            raise


def _delete_namespace(redshift_serverless, ns_name: str, timeout_s: float = 600.0) -> None:
    """Teardown: DeleteNamespace refuses with ConflictException while the namespace still
    finishes an operation (such as its workgroup's removal); retry only that, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift_serverless.delete_namespace(namespaceName=ns_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_warehouse_and_wait(redshift_serverless, wg_name: str, ns_name: str, timeout_s: float = 900.0) -> None:
    """Teardown: delete the workgroup (retrying ConflictException while it still finishes an
    operation) and wait until it is gone, then the namespace, so the network teardown registered
    before this finds the workgroup's network interfaces released."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _quiet_not_found(lambda: redshift_serverless.delete_workgroup(workgroupName=wg_name))
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_gone(lambda: redshift_serverless.get_workgroup(workgroupName=wg_name), f"workgroup {wg_name}")
    _quiet_not_found(lambda: _delete_namespace(redshift_serverless, ns_name))
    _wait_gone(lambda: redshift_serverless.get_namespace(namespaceName=ns_name), f"namespace {ns_name}")


def _wait_gone(probe, what: str, timeout_s: float = 900.0, interval_s: float = 2.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            probe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what} gone: the run budget ended first; not graded")
    raise AssertionError(f"{what} was not gone within {timeout_s}s")


def _create_network(ctx, ec2):
    """A VPC with one subnet in each of three AZs, owned by this check; returns
    ``(subnet_ids, teardown)``. ``teardown(wait_s)`` removes them, retrying while the
    workgroup's network interfaces linger; it is also registered as cleanup."""
    name = ctx.unique_name("sim2real-behav-rsintg-vpc-")
    tags = [{"Key": "Name", "Value": name}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    subnet_ids: list[str] = []

    def _teardown(wait_s: float = 900.0, run_ctx=None) -> None:
        deadline = time.monotonic() + wait_s
        steps = [(lambda sid=sid: ec2.delete_subnet(SubnetId=sid)) for sid in subnet_ids]
        steps.append(lambda: ec2.delete_vpc(VpcId=vpc_id))
        for step in steps:
            while True:
                try:
                    _quiet_not_found(step)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "DependencyViolation":
                        raise
                    if time.monotonic() >= deadline:
                        if run_ctx is not None and _budget_spent(run_ctx):
                            raise TimeoutError(
                                f"network of {vpc_id} released: the run budget ended first; not graded"
                            ) from exc
                        raise
                    time.sleep(2)

    ctx.on_cleanup(_teardown)
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= 3, f"region {ctx.region} does not expose >= 3 AZs to host a serverless workgroup"
    for index, az in enumerate(azs[:3]):
        subnet_ids.append(
            ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.0.{index}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
            )["Subnet"]["SubnetId"]
        )
    return list(subnet_ids), _teardown


def _wait_namespace_available(redshift_serverless, ns_name: str, timeout_s: float = 120.0, interval_s: float = 2.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = redshift_serverless.get_namespace(namespaceName=ns_name)
        last_status = resp["namespace"]["status"]
        if last_status == "AVAILABLE":
            return
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"namespace {ns_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"namespace {ns_name} did not become AVAILABLE within {timeout_s}s (last={last_status})")


def _wait_workgroup_available(redshift_serverless, wg_name: str, timeout_s: float = 900.0, interval_s: float = 2.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = redshift_serverless.get_workgroup(workgroupName=wg_name)
        last_status = resp["workgroup"]["status"]
        if last_status == "AVAILABLE":
            return
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"workgroup {wg_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"workgroup {wg_name} did not become AVAILABLE within {timeout_s}s (last={last_status})")


def _create_integration_with_retry(redshift, timeout_s: float = 240.0, interval_s: float = 2.0, ctx=None, **kwargs):
    """Retry, bounded, on the not-found fault CreateIntegration reports while a just-created
    namespace and its resource policy propagate."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return redshift.create_integration(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IntegrationTargetNotFoundFault":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError("CreateIntegration resolving its target: the run budget ended first; not graded") from exc
                raise
            time.sleep(interval_s)


def _delete_integration(redshift, arn: str, timeout_s: float, interval_s: float = 2.0, ctx=None) -> None:
    """DeleteIntegration refuses with IntegrationConflictOperationFault while the target data
    warehouse is not active (it is busy applying the integration); retry only that, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift.delete_integration(IntegrationArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IntegrationConflictOperationFault":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"DeleteIntegration {arn} accepted: the run budget ended first; not graded") from exc
                raise
        time.sleep(interval_s)


def _wait_integration_active(redshift, arn: str, timeout_s: float = 600.0, interval_s: float = 2.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = redshift.describe_integrations(IntegrationArn=arn)
        integrations = resp.get("Integrations") or []
        if integrations:
            last_status = integrations[0]["Status"]
            if last_status == "active":
                return
            if last_status in ("failed",):
                raise AssertionError(f"integration {arn} entered status {last_status!r} instead of active")
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"integration {arn} active: the run budget ended first; not graded")
    raise AssertionError(f"integration {arn} did not become active within {timeout_s}s (last={last_status})")


def _wait_integration_deleted(redshift, arn: str, timeout_s: float = 180.0, interval_s: float = 2.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = redshift.describe_integrations(IntegrationArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "IntegrationNotFoundFault":
                return
            raise
        if not resp.get("Integrations"):
            return
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"integration {arn} gone: the run budget ended first; not graded")
    raise AssertionError(f"integration {arn} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
