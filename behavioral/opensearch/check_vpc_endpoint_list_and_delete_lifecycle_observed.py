"""vpc-endpoint-list-and-delete-lifecycle-observed."""
from __future__ import annotations

import json
import time
import uuid
import zlib
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-endpoint-list-and-delete-lifecycle-observed"
GROUP = "deploy"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A VPC endpoint created for a CloudFormation-deployed VPC domain appears in
    ListVpcEndpointsForDomain once ACTIVE, and disappears from that list after deletion."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    opensearch = ctx.client("opensearch")

    _ensure_vpc_service_linked_role(ctx)
    vpc_id, domain_subnet, endpoint_subnet, sg_id = _create_isolated_network(ctx, ec2)

    domain_name = _short_name("sim2osdlc-")
    stack_name = ctx.unique_name("sim2real-osdlc-stack-")
    template_body = _domain_template_json(
        domain_name, {"SubnetIds": [domain_subnet], "SecurityGroupIds": [sg_id]}
    )

    def _delete_stack():
        # Bounded so the stack wait plus the network teardown window fit the suite's cleanup budget.
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 550}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_delete_stack)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800}
        )
    except Exception as exc:
        reasons = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatus')} {e.get('ResourceStatusReason', '')}"
            for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        ]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc

    domain = _poll_until(
        lambda: opensearch.describe_domain(DomainName=domain_name)["DomainStatus"],
        lambda d: d["Processing"] is False and d.get("Endpoints"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    domain_arn = domain["ARN"]

    endpoint_id = opensearch.create_vpc_endpoint(
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [endpoint_subnet], "SecurityGroupIds": [sg_id]},
    )["VpcEndpoint"]["VpcEndpointId"]

    def _delete_endpoint():
        try:
            opensearch.delete_vpc_endpoint(VpcEndpointId=endpoint_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete_endpoint)

    _poll_until(
        lambda: opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda e: e["Status"] == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )

    listed = opensearch.list_vpc_endpoints_for_domain(DomainName=domain_name)["VpcEndpointSummaryList"]
    assert any(e["VpcEndpointId"] == endpoint_id for e in listed), (
        f"endpoint {endpoint_id} missing from ListVpcEndpointsForDomain: {listed}"
    )

    opensearch.delete_vpc_endpoint(VpcEndpointId=endpoint_id)

    remaining = _poll_until(
        lambda: opensearch.list_vpc_endpoints_for_domain(DomainName=domain_name)["VpcEndpointSummaryList"],
        lambda lst: not any(e["VpcEndpointId"] == endpoint_id for e in lst),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert not any(e["VpcEndpointId"] == endpoint_id for e in remaining), (
        f"deleted endpoint {endpoint_id} still present in ListVpcEndpointsForDomain: {remaining}"
    )


def _ensure_vpc_service_linked_role(ctx) -> None:
    """A VPC-attached domain fails CreateDomain (an immediate CFN ROLLBACK_COMPLETE) unless the
    es.amazonaws.com service-linked role exists; it is not created implicitly.
    "InvalidInput" is the already-exists answer."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code not in ("InvalidInput", "InvalidInputException"):
            raise


def _short_name(prefix: str, maxlen: int = 28) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"[:maxlen]


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _create_isolated_network(ctx, ec2) -> tuple[str, str, str, str]:
    base_name = ctx.unique_name("sim2real-osd-vpclc-")
    octet = 16 + (zlib.crc32(base_name.encode()) % 200)
    vpc_cidr = f"10.{octet}.0.0/16"
    domain_cidr = f"10.{octet}.1.0/24"
    endpoint_cidr = f"10.{octet}.2.0/24"

    vpc_id = ec2.create_vpc(CidrBlock=vpc_cidr, TagSpecifications=_tag_spec("vpc", base_name))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    domain_subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=domain_cidr, AvailabilityZone=az,
        TagSpecifications=_tag_spec("subnet", f"{base_name}-domain"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_subnet", SubnetId=domain_subnet)))

    endpoint_subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=endpoint_cidr, AvailabilityZone=az,
        TagSpecifications=_tag_spec("subnet", f"{base_name}-endpoint"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_subnet", SubnetId=endpoint_subnet)))

    sg_id = ec2.create_security_group(
        GroupName=base_name,
        Description="sim2real opensearch vpc-endpoint lifecycle test",
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group", base_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))

    return vpc_id, domain_subnet, endpoint_subnet, sg_id


# The not-found codes of the network deletes: an already-absent resource is the only outcome a
# teardown tolerates.
_GONE_CODES = {"InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound"}


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _domain_template_json(domain_name: str, vpc_options: dict[str, Any] | None = None) -> str:
    props: dict[str, Any] = {
        "DomainName": domain_name,
        "EngineVersion": "OpenSearch_2.11",
        "ClusterConfig": {"InstanceType": "t3.small.search", "InstanceCount": 1},
        "EBSOptions": {"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        "AccessPolicies": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    # The deploying account's own principal, resolved by CloudFormation.
                    "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                    "Action": "es:*",
                    "Resource": "*",
                }
            ],
        },
    }
    if vpc_options:
        props["VPCOptions"] = vpc_options
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Domain": {"Type": "AWS::OpenSearchService::Domain", "Properties": props}},
        "Outputs": {"DomainArn": {"Value": {"Fn::GetAtt": ["Domain", "Arn"]}}},
    }
    return json.dumps(template)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# Resources in a VPC delete asynchronously and leave AWS-managed ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries DependencyViolation, then raises naming the ENIs left.
# The window is shared by all of one check's network deletes.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
