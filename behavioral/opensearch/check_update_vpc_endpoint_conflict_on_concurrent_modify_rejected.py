"""update-vpc-endpoint-conflict-on-concurrent-modify-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-vpc-endpoint-conflict-on-concurrent-modify-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint issued while a prior update on the same endpoint is still UPDATING is
    rejected with ConflictException; the in-flight config is not overwritten; a fresh update
    still succeeds once the endpoint settles back to ACTIVE."""
    opensearch = ctx.client("opensearch")
    domain_name, domain_arn = _create_vpc_domain(ctx)
    _wait_domain_active(ctx, domain_name, _budget_s(ctx, 1500.0))

    # UpdateVpcEndpoint is scoped to the VPC the endpoint was created in -- real AWS rejects a
    # subnet from any other VPC with ValidationException ("The specified subnet is not part of
    # the VPC"), so all three subnet/SG configs below live in ONE VPC.
    ep_vpc_id, subnet_b1, sg_b1 = _create_vpc_with_subnet(ctx, "10.92.0.0/16", "10.92.1.0/24")
    subnet_b2, sg_b2 = _create_subnet_and_sg(ctx, ep_vpc_id, "10.92.2.0/24")
    subnet_b3, sg_b3 = _create_subnet_and_sg(ctx, ep_vpc_id, "10.92.3.0/24")

    # Registered after every subnet, so it runs before any network delete: the endpoint's and the
    # domain's deletes are asynchronous and their ENIs block DeleteSubnet until both are gone.
    endpoint_ids: list = []
    ctx.on_cleanup(lambda: _release_endpoint_and_domain(ctx, endpoint_ids, domain_name))
    endpoint = _create_vpc_endpoint_when_ready(ctx, domain_arn, subnet_b1, sg_b1)
    endpoint_id = endpoint["VpcEndpointId"]
    endpoint_ids.append(endpoint_id)
    _wait_endpoint_status(ctx, endpoint_id, "ACTIVE")

    # The first update runs asynchronously; the conflicting one is issued as soon as it returns,
    # while it is still UPDATING.
    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id, VpcOptions={"SubnetIds": [subnet_b2], "SecurityGroupIds": [sg_b2]}
    )
    code, message = _error(
        lambda: opensearch.update_vpc_endpoint(
            VpcEndpointId=endpoint_id, VpcOptions={"SubnetIds": [subnet_b3], "SecurityGroupIds": [sg_b3]}
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "A update operation is already in progress for this VPC endpoint."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected update's subnet must not have been applied
    _wait_endpoint_status(ctx, endpoint_id, "ACTIVE")
    settled = _throttled(opensearch.describe_vpc_endpoints, VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    settled_subnets = settled["VpcOptions"]["SubnetIds"]
    assert subnet_b3 not in settled_subnets, (
        f"rejected update's subnet {subnet_b3!r} must not apply, got SubnetIds={settled_subnets!r}"
    )
    assert subnet_b2 in settled_subnets, (
        f"the first (accepted) update's subnet {subnet_b2!r} must still be applied, got "
        f"SubnetIds={settled_subnets!r}"
    )

    # positive control: now that the endpoint is settled, the same kind of update succeeds
    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id, VpcOptions={"SubnetIds": [subnet_b3], "SecurityGroupIds": [sg_b3]}
    )
    _wait_endpoint_status(ctx, endpoint_id, "ACTIVE")
    final = _throttled(opensearch.describe_vpc_endpoints, VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    final_subnets = final["VpcOptions"]["SubnetIds"]
    assert subnet_b3 in final_subnets, (
        f"identical update must succeed once settled, expected {subnet_b3!r} in SubnetIds, got "
        f"{final_subnets!r}"
    )

    # Release the endpoint's and the domain's ENIs before the network teardown runs: both deletes
    # are asynchronous, and their ENIs outlast the teardown window otherwise.
    _delete_endpoint_and_wait(ctx, endpoint_id, _budget_s(ctx, 900.0), capped=True)
    _delete_domain_and_wait(ctx, domain_name, _budget_s(ctx, 2400.0), capped=True)


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; raises if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# Concurrent checks in one account can be throttled, so a poll can be answered ThrottlingException;
# a throttled read is retried with backoff instead of failing the check.
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _throttled(fn, **kwargs):
    """fn(**kwargs), retried with exponential backoff (2-30 s, 8 attempts) while throttled."""
    from botocore.exceptions import ClientError

    for attempt in range(8):
        try:
            return fn(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == 7:
                raise
        time.sleep(min(30.0, 2.0 * 2**attempt))
    raise AssertionError("unreachable")


def _create_vpc_endpoint_when_ready(ctx, domain_arn, subnet_id, sg_id, timeout_s: float = 900.0) -> dict:
    """CreateVpcEndpoint can still refuse a domain that reports Created and Processing=False as
    "currently being created"; retry only that refusal, bounded."""
    from botocore.exceptions import ClientError

    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            return opensearch.create_vpc_endpoint(
                DomainArn=domain_arn, VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]}
            )["VpcEndpoint"]
        except ClientError as exc:
            error = exc.response["Error"]
            still_creating = error["Code"] == "ValidationException" and error.get("Message") == (
                "Unable to process request because the specified domain is currently being created."
            )
            if not still_creating or time.monotonic() >= deadline:
                if still_creating and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateVpcEndpoint domain-creating window: the run budget ended first; not graded"
                    ) from exc
                raise
        time.sleep(2)


def _ignore_not_found(fn, **kwargs) -> None:
    """A teardown delete that tolerates the resource already being gone."""
    from botocore.exceptions import ClientError

    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _release_endpoint_and_domain(ctx, endpoint_ids: list, domain_name: str) -> None:
    """Teardown: delete the endpoint (if created) and the domain, each waited until gone; a no-op
    for whatever run() already deleted."""
    for endpoint_id in endpoint_ids:
        _delete_endpoint_and_wait(ctx, endpoint_id, 600.0)
    _delete_domain_and_wait(ctx, domain_name, 1080.0)


def _delete_endpoint_and_wait(ctx, endpoint_id: str, timeout_s: float, capped: bool = False) -> None:
    """Delete the VPC endpoint (already gone is fine; retried while an update in flight refuses it
    with ConflictException) and poll until DescribeVpcEndpoints no longer returns it."""
    from botocore.exceptions import ClientError

    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _ignore_not_found(opensearch.delete_vpc_endpoint, VpcEndpointId=endpoint_id)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                if capped and exc.response["Error"]["Code"] == "ConflictException" and _budget_spent(ctx):
                    raise TimeoutError(
                        f"vpc endpoint {endpoint_id} delete: the run budget ended first; not graded"
                    ) from exc
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        if not _throttled(opensearch.describe_vpc_endpoints, VpcEndpointIds=[endpoint_id])["VpcEndpoints"]:
            return
        time.sleep(2)
    if capped and _budget_spent(ctx):
        raise TimeoutError(f"vpc endpoint {endpoint_id} deleted: the run budget ended first; not graded")
    raise AssertionError(f"vpc endpoint {endpoint_id} was not deleted within {timeout_s}s")


def _delete_domain_and_wait(ctx, domain_name: str, timeout_s: float, capped: bool = False) -> None:
    """Delete the domain (already gone is fine) and poll until DescribeDomain reports
    ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    opensearch = ctx.client("opensearch")
    _ignore_not_found(opensearch.delete_domain, DomainName=domain_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            _throttled(opensearch.describe_domain, DomainName=domain_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    if capped and _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} deleted: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} was not deleted within {timeout_s}s")


def _create_vpc_with_subnet(ctx, vpc_cidr: str, subnet_cidr: str) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-osvpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr, TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name + "-subnet"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id, GroupName=name + "-sg", Description="sim2real opensearch vpc-endpoint test sg"
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return vpc_id, subnet_id, sg_id


def _create_subnet_and_sg(ctx, vpc_id: str, subnet_cidr: str) -> tuple[str, str]:
    """A second (or third) subnet/SG pair within an EXISTING vpc -- UpdateVpcEndpoint only
    accepts subnets from the endpoint's own VPC, so distinct update targets must share one VPC."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-osvpc-")
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name + "-subnet"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id, GroupName=name + "-sg", Description="sim2real opensearch vpc-endpoint test sg"
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_id, sg_id


def _ensure_vpc_service_linked_role(ctx) -> None:
    """A VPC-attached CreateDomain fails without the ``es.amazonaws.com`` service-linked role and
    does not create it implicitly. ``InvalidInput`` is the already-exists answer.
    """
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _create_vpc_domain(ctx) -> tuple[str, str]:
    opensearch = ctx.client("opensearch")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-osd-").replace("_", "-").lower()[:28]
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{name}"
    _ensure_vpc_service_linked_role(ctx)
    _, subnet_id, sg_id = _create_vpc_with_subnet(ctx, "10.91.0.0/16", "10.91.1.0/24")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "es:*",
                        "Resource": f"{domain_arn}/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _ignore_not_found(opensearch.delete_domain, DomainName=name))
    return name, domain_arn


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1500.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _throttled(opensearch.describe_domain, DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} did not become active within {timeout_s}s")


def _wait_endpoint_status(ctx, endpoint_id: str, target: str, timeout_s: float = 600.0) -> None:
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _throttled(opensearch.describe_vpc_endpoints, VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]["Status"]
        if status == target:
            return
        if status.endswith("FAILED"):
            raise AssertionError(f"vpc endpoint {endpoint_id} entered {status}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"vpc endpoint {endpoint_id} {target}: the run budget ended first; not graded")
    raise AssertionError(f"vpc endpoint {endpoint_id} did not reach {target} within {timeout_s}s")


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
