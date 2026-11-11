"""update-vpc-endpoint-out-of-range-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-vpc-endpoint-out-of-range-config-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint with one more security group than the per-ENI quota raises
    ValidationException and keeps the original groups; a well-formed update then succeeds.
    """
    opensearch = ctx.client("opensearch")
    ec2 = ctx.client("ec2")

    _ensure_vpc_service_linked_role(ctx)
    # The security-groups-per-ENI quota is adjustable per account, so it is read, not hardcoded.
    excess_count = _security_groups_per_eni_quota(ctx) + 1
    vpc_id, domain_subnet, endpoint_subnet, sg_ids = _create_test_network(ctx, ec2, excess_count)
    initial_sg, final_sg = sg_ids[0], sg_ids[1]
    excess_sgs = sg_ids[2 : 2 + excess_count]  # one past the account's own ENI-SG quota
    domain_sg = sg_ids[2 + excess_count]

    domain_name = ctx.unique_name("sim2real-vpe")[:28].rstrip("-")
    domain_arn = opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [domain_subnet], "SecurityGroupIds": [domain_sg]},
    )["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: _delete_domain_ignore_missing(opensearch, domain_name))
    # CreateVpcEndpoint is rejected while the domain is still provisioning/processing a
    # config change -- wait for it to settle first.
    _wait_domain_not_processing(opensearch, domain_name, ctx=ctx)

    endpoint = opensearch.create_vpc_endpoint(
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [endpoint_subnet], "SecurityGroupIds": [initial_sg]},
    )["VpcEndpoint"]
    endpoint_id = endpoint["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_missing(opensearch, endpoint_id))
    _wait_endpoint_status(opensearch, endpoint_id, {"ACTIVE"}, ctx=ctx)

    code, message = _error_code(
        lambda: opensearch.update_vpc_endpoint(
            VpcEndpointId=endpoint_id,
            VpcOptions={"SubnetIds": [endpoint_subnet], "SecurityGroupIds": excess_sgs},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "You’ve exceeded the limit for security groups. "
        "You can select up to 5 security groups for the VPC endpoint."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the endpoint still carries only its original security group.
    unchanged = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][
        0
    ]
    assert unchanged["VpcOptions"]["SecurityGroupIds"] == [initial_sg], (
        f"rejected update mutated security groups: {unchanged['VpcOptions']!r}"
    )

    # Positive control: a well-formed update to the same endpoint succeeds.
    _wait_endpoint_status(opensearch, endpoint_id, {"ACTIVE"}, ctx=ctx)
    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        VpcOptions={"SubnetIds": [endpoint_subnet], "SecurityGroupIds": [final_sg]},
    )
    _wait_endpoint_status(opensearch, endpoint_id, {"ACTIVE"}, ctx=ctx)
    updated = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert updated["VpcOptions"]["SecurityGroupIds"] == [final_sg], (
        f"valid update did not persist: {updated['VpcOptions']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


def _ensure_vpc_service_linked_role(ctx) -> None:
    """Create the OpenSearch service-linked role, which a VPC-attached CreateDomain requires and,
    unlike a public domain, does not create implicitly. ``InvalidInput`` means it already exists.
    """
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _security_groups_per_eni_quota(ctx) -> int:
    quota = ctx.client("service-quotas").get_service_quota(
        ServiceCode="vpc", QuotaCode="L-2AFB9258"
    )["Quota"]
    return int(quota["Value"])


def _create_test_network(ctx, ec2, excess_count):
    tag_key = ctx.unique_name("sim2real-behav-osvpe-")

    def _tags(resource_type):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": tag_key}]}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16", TagSpecifications=_tags("vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_a, az_b = azs[0]["ZoneName"], azs[min(1, len(azs) - 1)]["ZoneName"]

    domain_subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.1.0/24",
        AvailabilityZone=az_a,
        TagSpecifications=_tags("subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_net(ec2, vpc_id, f"subnet {domain_subnet}", lambda: ec2.delete_subnet(SubnetId=domain_subnet))
    )

    endpoint_subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.2.0/24",
        AvailabilityZone=az_b,
        TagSpecifications=_tags("subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_net(ec2, vpc_id, f"subnet {endpoint_subnet}", lambda: ec2.delete_subnet(SubnetId=endpoint_subnet))
    )

    sg_ids = []
    for i in range(excess_count + 3):  # initial + final + excess_count + domain
        sg_id = ec2.create_security_group(
            GroupName=f"{tag_key}-sg-{i}",
            Description="sim2real behavioral test security group",
            VpcId=vpc_id,
            TagSpecifications=_tags("security-group"),
        )["GroupId"]
        sg_ids.append(sg_id)
        ctx.on_cleanup(
            lambda sg=sg_id: _delete_net(ec2, vpc_id, f"sg {sg}", lambda: ec2.delete_security_group(GroupId=sg))
        )

    return vpc_id, domain_subnet, endpoint_subnet, sg_ids


def _wait_endpoint_status(opensearch, endpoint_id, ok_statuses, timeout_s=300.0, interval_s=2.0,
                          ctx=None):
    fail_statuses = {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
    deadline = time.monotonic() + timeout_s
    while True:
        endpoints = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])[
            "VpcEndpoints"
        ]
        status = endpoints[0]["Status"] if endpoints else None
        if status in ok_statuses:
            return status
        assert status not in fail_statuses, f"vpc endpoint {endpoint_id} entered {status}"
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"vpc endpoint {endpoint_id} {ok_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"vpc endpoint {endpoint_id} never reached {ok_statuses} within {timeout_s}s")


def _delete_endpoint_ignore_missing(opensearch, endpoint_id):
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_vpc_endpoint(VpcEndpointId=endpoint_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_domain_ignore_missing(opensearch, domain_name):
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_not_processing(opensearch, domain_name, timeout_s=2400.0, interval_s=2.0,
                                ctx=None):
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
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
        # DomainProcessingStatus is the authoritative state machine ("Creating" ->
        # "Active"); Created/Processing can toggle before the domain is genuinely
        # usable for dependent calls like CreateVpcEndpoint.
        if status.get("Created") and status.get("DomainProcessingStatus") == "Active":
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} processing finished: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never finished processing within {timeout_s}s")



# The OpenSearch domain and VPC endpoint delete asynchronously and keep ENIs in the VPC for a
# while, so an immediate DeleteSecurityGroup / DeleteSubnet / DeleteVpc fails with
# DependencyViolation. Each network delete waits (bounded) for the VPC to hold no ENIs, retries
# DependencyViolation in the same window, then raises naming what still holds the VPC.
# The window is shared by all of one VPC's network deletes; a domain deleted mid-creation holds its
# ENIs past 840 s, so the window takes most of the suite's 1800 s cleanup budget.
_NET_TEARDOWN_S = 1500.0
_NET_DEADLINES: dict = {}


def _delete_net(ec2, vpc_id, label, delete) -> None:
    deadline = _NET_DEADLINES.setdefault(vpc_id, time.monotonic() + _NET_TEARDOWN_S)
    while _vpc_enis(ec2, vpc_id) and time.monotonic() < deadline:
        time.sleep(2)
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{label}: {code}; ENIs still in {vpc_id}: {_vpc_enis(ec2, vpc_id)}"
                ) from exc
        time.sleep(2)


def _vpc_enis(ec2, vpc_id) -> list:
    try:
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [
        f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}"
        for e in enis["NetworkInterfaces"]
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
