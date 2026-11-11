"""data-plane-vpc-endpoints-for-domain-listing-accuracy."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "data-plane-vpc-endpoints-for-domain-listing-accuracy"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVpcEndpointsForDomain scoped to domain A returns only A's VPC
    endpoint, excluding an endpoint that belongs to a sibling domain B."""
    aos = ctx.client("opensearch")
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _create_network(ctx, ec2)
    _ensure_vpc_service_linked_role(ctx)

    domain_a = _create_domain(ctx, aos, subnet_id, sg_id)
    domain_b = _create_domain(ctx, aos, subnet_id, sg_id)
    arn_a = _wait_domain_active(ctx, aos, domain_a)
    arn_b = _wait_domain_active(ctx, aos, domain_b)

    endpoint_a = _create_vpc_endpoint(ctx, aos, arn_a, subnet_id, sg_id)
    endpoint_b = _create_vpc_endpoint(ctx, aos, arn_b, subnet_id, sg_id)
    _wait_endpoint_active(ctx, aos, endpoint_a)
    _wait_endpoint_active(ctx, aos, endpoint_b)

    listed_for_a = _list_endpoint_ids(aos, domain_a)
    assert endpoint_a in listed_for_a, f"domain A's own endpoint missing from its listing: {listed_for_a}"
    assert endpoint_b not in listed_for_a, (
        f"domain B's endpoint {endpoint_b} leaked into domain A's ListVpcEndpointsForDomain: {listed_for_a}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_network(ctx, ec2):
    tag_spec = lambda kind, name: [{  # noqa: E731
        "ResourceType": kind,
        "Tags": [{"Key": "Name", "Value": name}],
    }]

    vpc_name = ctx.unique_name("sim2real-aos-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/24",
        TagSpecifications=tag_spec("vpc", vpc_name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_name = ctx.unique_name("sim2real-aos-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.0.0/25",
        TagSpecifications=tag_spec("subnet", subnet_name),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_name = ctx.unique_name("sim2real-aos-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real opensearch vpc-endpoint isolation check",
        VpcId=vpc_id,
        TagSpecifications=tag_spec("security-group", sg_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    return subnet_id, sg_id


def _ensure_vpc_service_linked_role(ctx) -> None:
    """Create the service-linked role a VPC CreateDomain requires; it must be es.amazonaws.com,
    not opensearchservice.amazonaws.com. InvalidInput means it already exists."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _create_domain(ctx, aos, subnet_id: str, sg_id: str) -> str:
    # A public domain rejects CreateVpcEndpoint with DisabledOperationException.
    name = ctx.unique_name("sim2real-aos-dom-").lower()[:28].rstrip("-")
    aos.create_domain(
        DomainName=name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    ctx.on_cleanup(lambda: aos.delete_domain(DomainName=name))
    return name


def _wait_domain_active(ctx, aos, domain_name: str) -> str:
    def _status():
        return aos.describe_domain(DomainName=domain_name)["DomainStatus"]

    status = _poll_until(
        _status,
        lambda s: s.get("Created") and not s.get("Processing"),
        timeout_s=1800,
        interval_s=30,
    )
    return status["ARN"]


def _create_vpc_endpoint(ctx, aos, domain_arn: str, subnet_id: str, sg_id: str, *, timeout_s=600.0, interval_s=15.0) -> str:
    # CreateVpcEndpoint can briefly reject with ValidationException ("currently processing
    # changes") after DescribeDomain already reports Created/!Processing.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = aos.create_vpc_endpoint(
                DomainArn=domain_arn,
                VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            last_err = exc
            time.sleep(interval_s)
    else:
        raise last_err
    endpoint_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: aos.delete_vpc_endpoint(VpcEndpointId=endpoint_id))
    return endpoint_id


def _wait_endpoint_active(ctx, aos, endpoint_id: str) -> None:
    def _status() -> str:
        return aos.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]["Status"]

    status = _poll_until(_status, lambda s: s in ("ACTIVE", "CREATE_FAILED"), timeout_s=900, interval_s=15)
    assert status == "ACTIVE", f"vpc endpoint entered {status}, not ACTIVE"


def _list_endpoint_ids(aos, domain_name: str) -> set:
    ids: set = set()
    next_token = None
    while True:
        kwargs = {"DomainName": domain_name}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = aos.list_vpc_endpoints_for_domain(**kwargs)
        for summary in resp.get("VpcEndpointSummaryList", []):
            ids.add(summary["VpcEndpointId"])
        next_token = resp.get("NextToken") or None
        if not next_token:
            break
    return ids


# Domains and VPC endpoints delete asynchronously and keep ENIs in the subnet meanwhile, so
# network deletes fail with DependencyViolation in that window. Each delete waits (bounded, shared
# per check) for the ENIs to go, retries, and raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
