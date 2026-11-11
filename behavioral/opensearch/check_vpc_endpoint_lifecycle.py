"""vpc-endpoint-lifecycle."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-endpoint-lifecycle"
GROUP = 'vpc-endpoint'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _ensure_vpc_service_linked_role(ctx) -> None:
    """Create the ``es.amazonaws.com`` service-linked role VPC CreateDomain needs and never creates.

    Only this role (not ``opensearchservice.amazonaws.com``) grants VPC access; ``InvalidInput``
    is the already-exists answer."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _ec2_tag_specs(resource_type: str) -> list:
    return [{
        "ResourceType": resource_type,
        "Tags": [{"Key": "sim2real", "Value": "behav"}],
    }]


def _default_vpc_subnet_and_sg(ctx, ec2) -> "tuple[str, str, str]":
    """Reuse the context's shared network and one of its subnets (avoids VpcLimitExceeded);
    only a fresh, tracked security group is created."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_id = subnets[0]["SubnetId"]
    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real behavioral opensearch vpc endpoint sg (default vpc)",
        VpcId=vpc_id,
        TagSpecifications=_ec2_tag_specs("security-group"),
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ec2, sg_id))
    return vpc_id, subnet_id, sg_id


def _delete_vpc_endpoint_quietly(osc, vpc_endpoint_id) -> None:
    """Teardown: the check deletes the endpoint itself, so a not-found here is the normal case."""
    try:
        osc.delete_vpc_endpoint(VpcEndpointId=vpc_endpoint_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


# The domain and VPC endpoint delete asynchronously and their requester-managed ENIs hold the
# security groups for minutes, so DeleteSecurityGroup fails with DependencyViolation; each delete
# waits for the ENIs within one shared bounded window, retries, then raises naming the ENIs.
_SG_TEARDOWN_S = 660.0
_SG_DEADLINE: list = []


def _delete_sg(ec2, sg_id) -> None:
    if not _SG_DEADLINE:
        _SG_DEADLINE.append(time.monotonic() + _SG_TEARDOWN_S)
    deadline = _SG_DEADLINE[0]
    while _sg_enis(ec2, sg_id) and time.monotonic() < deadline:
        time.sleep(15)
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"sg {sg_id}: {code}; ENIs still attached: {_sg_enis(ec2, sg_id)}"
                ) from exc
        time.sleep(15)


def _sg_enis(ec2, sg_id) -> list:
    try:
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [sg_id]}])
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [e["NetworkInterfaceId"] for e in enis["NetworkInterfaces"]]


def _create_domain(ctx, osc, domain_name, *, vpc_options) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        VPCOptions=vpc_options,
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            _err = _e.response.get("Error", {})
            _retryable = _err.get("Code") in _THROTTLE_CODES or (
                _err.get("Code") == "ValidationException"
                and "service-linked role" in _err.get("Message", "")
            )
            # A just-created service-linked role takes seconds to propagate; until then
            # CreateDomain still rejects with this ValidationException.
            if not _retryable:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still failing (throttle or service-linked-role propagation) after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True; a domain needs 10-20 min to go Active."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became Active within {budget}s")


def _retry_on(fn, *, error_codes=(), message_substrings=(), attempts=6, delay_s=10.0):
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if attempt < attempts - 1 and (
                code in error_codes or any(s in msg for s in message_substrings)
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=6.0, description="condition"):
    """Poll ``probe`` until ``predicate``; raise AssertionError once ``timeout_s`` passes."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcEndpoint on a VPC domain reaches ACTIVE and is listed globally and per domain;
    UpdateVpcEndpoint swaps its security group; after DeleteVpcEndpoint it is ENDPOINT_NOT_FOUND
    and UpdateVpcEndpoint fails ResourceNotFoundException."""
    osc = ctx.client("opensearch")
    ec2 = ctx.client("ec2")
    # Jitter the start: CreateDomain/CreateVpcEndpoint calls in lockstep with other checks
    # in the same account make ThrottlingException far more likely.
    time.sleep(random.uniform(0, 20.0))

    _ensure_vpc_service_linked_role(ctx)
    domain_vpc_id, domain_subnet_id, domain_sg_id = _default_vpc_subnet_and_sg(ctx, ec2)
    _vpc_id2, endpoint_subnet_id, endpoint_sg_id = _default_vpc_subnet_and_sg(ctx, ec2)
    sg2 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg2-"),
        Description="second sg for vpc endpoint update",
        VpcId=domain_vpc_id,
        TagSpecifications=_ec2_tag_specs("security-group"),
    )
    sg2_id = sg2["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ec2, sg2_id))

    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    created = _create_domain(
        ctx, osc, domain,
        vpc_options={"SubnetIds": [domain_subnet_id], "SecurityGroupIds": [domain_sg_id]},
    )
    domain_arn = created["ARN"]
    _wait_domain_active(osc, domain)

    ep = _retry_on(
        lambda: osc.create_vpc_endpoint(
            DomainArn=domain_arn,
            VpcOptions={"SubnetIds": [endpoint_subnet_id], "SecurityGroupIds": [endpoint_sg_id]},
        ),
        error_codes=("ValidationException",),
        message_substrings=("currently being created",),
    )["VpcEndpoint"]
    vpc_endpoint_id = ep["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_quietly(osc, vpc_endpoint_id))

    active = _poll_until(
        lambda: osc.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])["VpcEndpoints"][0],
        lambda e: e.get("Status") in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=900,
        description=f"vpc endpoint {vpc_endpoint_id} active",
    )
    assert active["Status"] == "ACTIVE", f"vpc endpoint failed to become ACTIVE: {active}"
    assert active["VpcOptions"]["SecurityGroupIds"] == [endpoint_sg_id]

    described = osc.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])["VpcEndpoints"]
    assert described and described[0]["VpcEndpointId"] == vpc_endpoint_id

    osc.update_vpc_endpoint(
        VpcEndpointId=vpc_endpoint_id,
        VpcOptions={"SubnetIds": [endpoint_subnet_id], "SecurityGroupIds": [sg2_id]},
    )
    updated = _poll_until(
        lambda: osc.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])["VpcEndpoints"][0],
        lambda e: e.get("Status") in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=900,
        description=f"vpc endpoint {vpc_endpoint_id} updated",
    )
    assert updated["Status"] == "ACTIVE"
    assert updated["VpcOptions"]["SecurityGroupIds"] == [sg2_id]

    global_list = {e["VpcEndpointId"] for e in osc.list_vpc_endpoints()["VpcEndpointSummaryList"]}
    assert vpc_endpoint_id in global_list

    domain_list = {
        e["VpcEndpointId"]
        for e in osc.list_vpc_endpoints_for_domain(DomainName=domain)["VpcEndpointSummaryList"]
    }
    assert vpc_endpoint_id in domain_list

    osc.delete_vpc_endpoint(VpcEndpointId=vpc_endpoint_id)

    def probe() -> str:
        resp = osc.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
        if resp.get("VpcEndpointErrors"):
            return "GONE"
        eps = resp.get("VpcEndpoints", [])
        if not eps:
            return "GONE"
        return eps[0].get("Status", "")

    _poll_until(
        probe,
        lambda s: s in ("GONE", "DELETED"),
        timeout_s=600,
        interval_s=2.0,
        description=f"vpc endpoint {vpc_endpoint_id} deleted",
    )

    global_list_after = {e["VpcEndpointId"] for e in osc.list_vpc_endpoints()["VpcEndpointSummaryList"]}
    assert vpc_endpoint_id not in global_list_after

    final = osc.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
    final_errors = final.get("VpcEndpointErrors", [])
    assert final_errors and final_errors[0]["ErrorCode"] == "ENDPOINT_NOT_FOUND", (
        f"expected ENDPOINT_NOT_FOUND for deleted {vpc_endpoint_id}, got {final}"
    )

    try:
        osc.update_vpc_endpoint(
            VpcEndpointId=vpc_endpoint_id,
            VpcOptions={"SubnetIds": [endpoint_subnet_id], "SecurityGroupIds": [endpoint_sg_id]},
        )
        raise AssertionError(f"UpdateVpcEndpoint on deleted {vpc_endpoint_id} unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        expected = "The VPC endpoint doesn't exist, or you don't have access to it."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
