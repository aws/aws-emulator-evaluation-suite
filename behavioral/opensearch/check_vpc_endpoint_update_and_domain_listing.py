"""vpc-endpoint-update-and-domain-listing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-endpoint-update-and-domain-listing"
GROUP = "state-machine"
SERVICES = ["opensearch"]

_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint's new VpcOptions are reflected by DescribeVpcEndpoints and the domain listing."""
    _ensure_opensearch_service_linked_role(ctx)
    subnet_id, sg1_id, sg2_id = _create_network(ctx)
    domain_name, domain_arn = _start_vpc_domain_creation(ctx, subnet_id, sg1_id)

    osv = ctx.client("opensearch")

    # On real AWS, CreateVpcEndpoint is rejected with a ValidationException ("Unable to process
    # request because the specified domain is currently processing changes") until the domain
    # finishes its initial creation, and (per observation) sometimes for a short extra window even
    # AFTER DescribeDomain itself reports Created/!Processing -- the VPC-endpoint subsystem's own
    # view of domain readiness lags slightly behind the domain's own Active transition (the same
    # kind of lag already handled for maintenance/migration elsewhere in this suite). Waiting for
    # DescribeDomain to report Active and THEN separately retrying CreateVpcEndpoint stacks two
    # sequential waits for essentially the same underlying "domain not ready yet" condition. Fold
    # both into ONE bounded retry loop instead, so the total wait is bounded by whichever settles
    # last rather than the sum of the two.
    created = _create_vpc_endpoint_with_retry(
        osv, domain_arn, subnet_id, sg1_id, timeout_s=1800.0,
    )
    vpc_endpoint_id = created["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc_endpoint(osv, vpc_endpoint_id))

    _wait_vpc_endpoint_status(osv, vpc_endpoint_id, {"ACTIVE", "CREATE_FAILED"}, timeout_s=1800)
    initial = _describe_vpc_endpoint(osv, vpc_endpoint_id)
    assert initial["Status"] == "ACTIVE", f"endpoint failed to become ACTIVE: {initial['Status']!r}"
    assert initial["VpcOptions"]["SecurityGroupIds"] == [sg1_id], (
        f"expected initial security group {[sg1_id]!r}, got {initial['VpcOptions']['SecurityGroupIds']!r}"
    )

    _call_with_backoff(
        osv.update_vpc_endpoint,
        VpcEndpointId=vpc_endpoint_id,
        VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg2_id]},
    )
    _wait_vpc_endpoint_status(osv, vpc_endpoint_id, {"ACTIVE", "UPDATE_FAILED"}, timeout_s=1800)

    updated = _describe_vpc_endpoint(osv, vpc_endpoint_id)
    assert updated["Status"] == "ACTIVE", f"endpoint update failed: {updated['Status']!r}"
    assert updated["VpcOptions"]["SecurityGroupIds"] == [sg2_id], (
        f"UpdateVpcEndpoint did not persist the new security group: {updated['VpcOptions']}"
    )

    listed = _call_with_backoff(osv.list_vpc_endpoints_for_domain, DomainName=domain_name)["VpcEndpointSummaryList"]
    matches = [e for e in listed if e["VpcEndpointId"] == vpc_endpoint_id]
    assert matches, "updated endpoint missing from ListVpcEndpointsForDomain"
    assert matches[0]["Status"] == "ACTIVE", (
        f"expected ACTIVE in ListVpcEndpointsForDomain after update, got {matches[0]['Status']!r}"
    )


# ===== self-contained helpers =====

def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff.

    Domain-creating checks in this suite tend to run close together against the same
    account, which can exceed the account's request rate for Describe*/List* calls and
    exhaust botocore's own retry budget. Back off and retry those transient throttling
    errors ourselves instead of letting hidden botocore retries silently eat into the
    harness's wall-clock budget (this VPC-endpoint check in particular runs many extra
    Describe/List/Create/Update calls across EC2, IAM, and OpenSearch, so it's especially
    exposed to a rate limit shared with the OTHER domain-heavy checks in this suite), or
    failing the check outright.
    """
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_err = err
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_err


def _ensure_opensearch_service_linked_role(ctx) -> None:
    """A VPC-attached OpenSearch domain requires the
    AWSServiceRoleForAmazonElasticsearchService service-linked role to exist first;
    CreateDomain does not create it automatically and instead fails with
    ValidationException ("you must enable a service-linked role...") if it's missing.

    The service name is ``es.amazonaws.com``, NOT ``opensearchservice.amazonaws.com`` --
    those create two DIFFERENT roles and only ``es.amazonaws.com`` ->
    AWSServiceRoleForAmazonElasticsearchService grants VPC access. Confirmed on real AWS:
    creating the ``opensearchservice.amazonaws.com`` role and then calling a VPC
    CreateDomain still fails with "you must enable a service-linked role...".
    """
    iam = ctx.client("iam")
    try:
        _call_with_backoff(iam.create_service_linked_role, AWSServiceName="es.amazonaws.com")
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise



def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
    }


def _create_network(ctx) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-vpce-vpc-")
    vpc = _call_with_backoff(
        ec2.create_vpc, CidrBlock=_VPC_CIDR, TagSpecifications=[_tag_spec("vpc", vpc_name)]
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ec2, vpc_id))

    azs = _call_with_backoff(ec2.describe_availability_zones)["AvailabilityZones"]
    az = azs[0]["ZoneName"]
    subnet_name = ctx.unique_name("sim2real-vpce-subnet-")
    subnet = _call_with_backoff(
        ec2.create_subnet,
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", subnet_name)],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _safe_delete_subnet(ec2, vpc_id, subnet_id))

    sg1_name = ctx.unique_name("sim2real-vpce-sg1-")
    sg1 = _call_with_backoff(
        ec2.create_security_group,
        GroupName=sg1_name,
        Description="sim2real behavioral check - initial",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", sg1_name)],
    )
    sg1_id = sg1["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_sg(ec2, vpc_id, sg1_id))

    sg2_name = ctx.unique_name("sim2real-vpce-sg2-")
    sg2 = _call_with_backoff(
        ec2.create_security_group,
        GroupName=sg2_name,
        Description="sim2real behavioral check - updated",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", sg2_name)],
    )
    sg2_id = sg2["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_sg(ec2, vpc_id, sg2_id))

    return subnet_id, sg1_id, sg2_id


def _short_domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real-{tag}-").lower()
    if len(raw) > 28:
        raw = raw[-28:]
    if not raw[0].isalpha():
        raw = "d" + raw[1:]
    return raw


def _start_vpc_domain_creation(ctx, subnet_id: str, sg_id: str) -> tuple[str, str]:
    osv = ctx.client("opensearch")
    domain_name = _short_domain_name(ctx, "ve")
    resp = _call_with_backoff(
        osv.create_domain,
        DomainName=domain_name,
        # Pinning to a known engine version (instead of letting CreateDomain default to
        # whatever the latest release happens to be) matters here: the default has been
        # observed taking noticeably longer to provision than this pinned version, which
        # is the difference between comfortably finishing domain + VPC endpoint
        # provisioning within the harness's wall-clock budget and blowing through it.
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_domain(osv, domain_name))
    return domain_name, domain_arn



def _create_vpc_endpoint_with_retry(
    osv, domain_arn: str, subnet_id: str, sg_id: str, timeout_s: float = 1800.0, interval_s: float = 15.0
) -> dict:
    """CreateVpcEndpoint is rejected with ValidationException ("Unable to process request
    because the specified domain is currently processing changes") for as long as the domain
    is still finishing its initial creation, AND (per observation) for a short extra window
    even after DescribeDomain itself reports Created/!Processing -- the VPC-endpoint
    subsystem's own view of domain readiness lags slightly behind the domain's Active
    transition. Retry on that specific error for a bounded window that covers BOTH phases
    (rather than a separate DescribeDomain-based wait followed by a second, narrower retry
    window here); any other error is fatal."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return _call_with_backoff(
                osv.create_vpc_endpoint,
                DomainArn=domain_arn,
                VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
            )
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err



def _describe_vpc_endpoint(osv, vpc_endpoint_id: str) -> dict:
    resp = _call_with_backoff(osv.describe_vpc_endpoints, VpcEndpointIds=[vpc_endpoint_id])
    endpoints = resp.get("VpcEndpoints", [])
    assert endpoints, f"DescribeVpcEndpoints returned nothing for {vpc_endpoint_id}"
    return endpoints[0]



def _wait_vpc_endpoint_status(osv, vpc_endpoint_id: str, terminal: set[str], timeout_s: float = 1800.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_vpc_endpoint(osv, vpc_endpoint_id)["Status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"vpc endpoint {vpc_endpoint_id} did not reach {terminal} within {timeout_s}s (last={last})")


def _safe_delete_vpc_endpoint(osv, vpc_endpoint_id: str) -> None:
    """Delete the endpoint and watch it leave DELETING for a short window; the network teardown
    behind it waits for its ENIs, so this does not block on full completion."""
    try:
        _call_with_backoff(osv.delete_vpc_endpoint, VpcEndpointId=vpc_endpoint_id)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            status = _describe_vpc_endpoint(osv, vpc_endpoint_id)["Status"]
        except AssertionError:
            return  # absent from DescribeVpcEndpoints: deleted
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if status in ("DELETING",):
            time.sleep(2)
            continue
        return


def _safe_delete_domain(osv, domain_name: str) -> None:
    """Delete the domain and watch it for a short window; deletion continues in the background,
    and the subnet/SG/VPC teardown behind it (`_delete_net`) waits for the domain's ENIs to leave."""
    try:
        _call_with_backoff(osv.delete_domain, DomainName=domain_name)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            _call_with_backoff(osv.describe_domain, DomainName=domain_name)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)



def _safe_delete_sg(ec2, vpc_id: str, sg_id: str) -> None:
    _delete_net(ec2, vpc_id, f"sg {sg_id}", lambda: _call_with_backoff(ec2.delete_security_group, GroupId=sg_id))


def _safe_delete_subnet(ec2, vpc_id: str, subnet_id: str) -> None:
    _delete_net(ec2, vpc_id, f"subnet {subnet_id}", lambda: _call_with_backoff(ec2.delete_subnet, SubnetId=subnet_id))


def _safe_delete_vpc(ec2, vpc_id: str) -> None:
    _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: _call_with_backoff(ec2.delete_vpc, VpcId=vpc_id))


# Check-created VPC networking is torn down only once the AWS-managed ENIs inside it are gone.
# Holders here: the OpenSearch VPC domain and its VPC endpoint, which delete asynchronously and keep
# ENIs in the subnet meanwhile, so an immediate DeleteSecurityGroup / DeleteSubnet / DeleteVpc fails
# with DependencyViolation. Every network delete waits (bounded) for the VPC to hold no ENIs,
# retries DependencyViolation within the SAME window, and raises naming what still holds the VPC.
# The window is shared by all of one VPC's network deletes and fits the suite's cleanup budget.
_NET_TEARDOWN_S = 720.0
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
