"""overly-permissive-vpc-endpoint-update-invalid-security-group-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "overly-permissive-vpc-endpoint-update-invalid-security-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint referencing a nonexistent security group must be rejected
    and must leave the endpoint's security groups unchanged, while updating to a
    valid, real security group in the same VPC still succeeds."""
    ec2 = ctx.client("ec2")
    opensearch = ctx.client("opensearch")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision a VPC-based OpenSearch domain")
    vpc_id = vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"shared network VPC {vpc_id} has no subnets available")
    subnet_id = subnets[0]["SubnetId"]

    default_sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not default_sgs:
        raise AssertionError(f"shared network VPC {vpc_id} has no default security group")
    default_sg_id = default_sgs[0]["GroupId"]

    _ensure_vpc_service_linked_role(ctx)

    domain_name = _domain_name(ctx)
    _create_vpc_domain_with_slr_retry(
        opensearch,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 120.0),
        DomainName=domain_name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [default_sg_id]},
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    domain_arn = _wait_domain_active(ctx, opensearch, domain_name)["ARN"]

    endpoint = _create_vpc_endpoint_with_domain_creating_retry(
        opensearch,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 300.0),
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [default_sg_id]},
    )["VpcEndpoint"]
    endpoint_id = endpoint["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_and_wait(opensearch, endpoint_id))
    _wait_vpc_endpoint_status(ctx, opensearch, endpoint_id, "ACTIVE")

    # Negative: a syntactically valid but nonexistent security group ID must be rejected.
    code, message = _error_code(
        lambda: opensearch.update_vpc_endpoint(
            VpcEndpointId=endpoint_id,
            VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": ["sg-00000000000000000"]},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == 'Invalid id: "sg-00000000000000000"', f"ValidationException message {message!r}"

    # Effect absent: the endpoint still has its original security group and is ACTIVE.
    unchanged = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert unchanged["Status"] == "ACTIVE"
    assert unchanged["VpcOptions"]["SecurityGroupIds"] == [default_sg_id]

    # Positive control: a valid, real security group in the same VPC is accepted.
    sg_name = _sg_name(ctx)
    new_sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral fidelity check security group",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "Name", "Value": sg_name}],
            }
        ],
    )
    new_sg_id = new_sg["GroupId"]
    # The endpoint holds this group until it is gone, and cleanups run last-in first-out.
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, new_sg_id))
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_and_wait(opensearch, endpoint_id))

    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [new_sg_id]},
    )
    _wait_vpc_endpoint_status(ctx, opensearch, endpoint_id, "ACTIVE")
    updated = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert updated["VpcOptions"]["SecurityGroupIds"] == [new_sg_id]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _domain_name(ctx) -> str:
    import uuid

    return f"sim2real-{uuid.uuid4().hex[:12]}"


def _sg_name(ctx) -> str:
    import uuid

    return f"sim2real-behav-sg-{uuid.uuid4().hex[:10]}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_vpc_domain_with_slr_retry(opensearch, *, ctx, timeout_s: float = 120.0, **kwargs) -> None:
    """CreateDomain right after CreateServiceLinkedRole can still reject with the
    "must enable a service-linked role" ValidationException while IAM propagates the
    role -- an eventual-consistency window, not a real rejection. Bounded retry only
    for that exact message; any other error (or the window's expiry) raises.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            opensearch.create_domain(**kwargs)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "ValidationException" or "service-linked role" not in err.get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateDomain service-linked role propagation: the run budget ended first; not graded"
                    ) from exc
                raise AssertionError(
                    f"CreateDomain still rejects for a missing VPC service-linked role after "
                    f"{timeout_s}s of IAM propagation wait: {err.get('Message')}"
                ) from exc
            time.sleep(2)


def _create_vpc_endpoint_with_domain_creating_retry(opensearch, *, ctx, timeout_s: float = 300.0, **kwargs) -> dict:
    """`Created=True, Processing=False` on DescribeDomain can still precede the point
    where CreateVpcEndpoint is accepted -- real AWS answers "the specified domain is
    currently being created" for a short window after. Bounded retry only for that
    exact message; any other error (or the window's expiry) raises.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return opensearch.create_vpc_endpoint(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "ValidationException" or "currently being created" not in err.get(
                "Message", ""
            ):
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateVpcEndpoint domain-creating window: the run budget ended first; not graded"
                    ) from exc
                raise AssertionError(
                    f"CreateVpcEndpoint still rejects with a domain-creating message after "
                    f"{timeout_s}s: {err.get('Message')}"
                ) from exc
            time.sleep(2)


def _ensure_vpc_service_linked_role(ctx) -> None:
    """Create the OpenSearch VPC service-linked role if this account doesn't have it yet.

    A VPC-attached CreateDomain hard-fails without it, and unlike a public domain it is not created
    implicitly. The role is `es.amazonaws.com` -> AWSServiceRoleForAmazonElasticsearchService (NOT
    `opensearchservice.amazonaws.com`, a different role that does not grant VPC access). Every target
    is asked the same way: the role is an IAM prerequisite of the VPC plumbing, not behavior under
    test.
    """
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _wait_domain_active(ctx, opensearch, domain_name, timeout_s: float = 1800.0) -> dict:
    from botocore.exceptions import ClientError

    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # DescribeDomain throttles under the suite's concurrent polls: poll again to the deadline.
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        if status.get("Created") and not status.get("Processing"):
            return status
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


def _wait_vpc_endpoint_status(ctx, opensearch, endpoint_id, want_status, timeout_s: float = 900.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        vpc_endpoints = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
        if vpc_endpoints and vpc_endpoints[0]["Status"] == want_status:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"VPC endpoint {endpoint_id} {want_status}: the run budget ended first; not graded")
    raise AssertionError(f"VPC endpoint {endpoint_id} never reached {want_status} within {timeout_s}s")


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_vpc_endpoint_and_wait(opensearch, endpoint_id, timeout_s=900.0, interval_s=15.0):
    """Delete an OpenSearch VPC endpoint and wait until it is gone, so its security groups are free."""
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_vpc_endpoint(VpcEndpointId=endpoint_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"OpenSearch VPC endpoint {endpoint_id} still exists {timeout_s:.0f}s after its delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
