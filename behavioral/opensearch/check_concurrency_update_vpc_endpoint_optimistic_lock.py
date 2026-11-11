"""concurrency-update-vpc-endpoint-optimistic-lock."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrency-update-vpc-endpoint-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["opensearch"]

_MAX_ATTEMPTS = 5


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two back-to-back UpdateVpcEndpoint calls, the first applies and the second, sent while
    the first is updating, gets ConflictException; the endpoint ends with only the first's
    SecurityGroupIds, and a later update to the second's config still succeeds."""
    ctx.client("ec2")
    opensearch = ctx.client("opensearch")
    _ensure_opensearch_vpc_service_linked_role(ctx)

    vpc = _create_vpc_stack(ctx, num_sg=2)
    name = _domain_name(ctx, "vpcep")
    create_resp = opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        VPCOptions={"SubnetIds": [vpc["subnet_id"]], "SecurityGroupIds": [vpc["sg_ids"][0]]},
    )
    domain_arn = create_resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=name))
    _wait_domain_active(ctx, name)

    ep_resp = opensearch.create_vpc_endpoint(
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [vpc["subnet_id"]], "SecurityGroupIds": [vpc["sg_ids"][0]]},
    )
    endpoint_id = ep_resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: opensearch.delete_vpc_endpoint(VpcEndpointId=endpoint_id))
    _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE"})

    sg_a, sg_b = vpc["sg_ids"][0], vpc["sg_ids"][1]

    def _update(sg_id):
        return opensearch.update_vpc_endpoint(
            VpcEndpointId=endpoint_id,
            VpcOptions={"SubnetIds": [vpc["subnet_id"]], "SecurityGroupIds": [sg_id]},
        )

    # Sequential, so the in-flight update is deterministic (a true race has no documented
    # outcome): the second call lands while the first is still updating. A first update that has
    # already settled when read back missed that window, so the pair is retried after it settles.
    outcomes = []
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        first_sg, second_sg = (sg_a, sg_b) if attempt % 2 else (sg_b, sg_a)
        outcomes = []
        for sg_id in (first_sg, second_sg):
            if outcomes:
                in_flight = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])[
                    "VpcEndpoints"
                ][0].get("Status")
                if in_flight != "UPDATING":
                    break
            try:
                _update(sg_id)
                outcomes.append(("ok", sg_id))
            except Exception as e:
                error = getattr(e, "response", {}).get("Error", {})
                outcomes.append(("error", error.get("Code"), error.get("Message")))
        if len(outcomes) == 2:
            break
        settled = _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE", "UPDATE_FAILED"})
        assert outcomes == [("ok", first_sg)] and settled["Status"] == "ACTIVE", (
            f"expected the first UpdateVpcEndpoint to apply and settle ACTIVE, got "
            f"outcomes={outcomes} status={settled['Status']!r}"
        )
    assert len(outcomes) == 2, (
        f"never caught the first UpdateVpcEndpoint still UPDATING in {_MAX_ATTEMPTS} attempts"
    )

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner, got outcomes={outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got outcomes={outcomes}"
    assert failures[0][1] == "ConflictException", f"expected ConflictException, got {failures[0][1]!r}"
    assert failures[0][2] == "A update operation is already in progress for this VPC endpoint.", (
        f"ConflictException message {failures[0][2]!r}"
    )

    winner_sg = successes[0][1]
    final = _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE", "UPDATE_FAILED"})
    assert final["Status"] == "ACTIVE", f"expected endpoint to settle ACTIVE after the race, got {final['Status']!r}"
    final_sgs = final["VpcOptions"]["SecurityGroupIds"]
    assert final_sgs == [winner_sg], f"final SecurityGroupIds {final_sgs} != winner's [{winner_sg}]"

    # Control: the rejection was the in-flight conflict, not a refusal of this config.
    loser_sg = sg_b if winner_sg == sg_a else sg_a
    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        VpcOptions={"SubnetIds": [vpc["subnet_id"]], "SecurityGroupIds": [loser_sg]},
    )
    control = _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE", "UPDATE_FAILED"})
    assert control["Status"] == "ACTIVE", f"control update did not settle ACTIVE, got {control['Status']!r}"
    control_sgs = control["VpcOptions"]["SecurityGroupIds"]
    assert control_sgs == [loser_sg], f"control update did not apply: expected [{loser_sg}], got {control_sgs}"


def _ensure_opensearch_vpc_service_linked_role(ctx) -> None:
    """Create the es.amazonaws.com service-linked role a VPC CreateDomain requires and does not
    create itself; InvalidInput/InvalidInputException means it already exists."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="es.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("InvalidInput", "InvalidInputException"):
            raise


def _domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real{tag}").lower()
    name = "".join(ch for ch in raw if ch.isalnum() or ch == "-")[:28].rstrip("-")
    return name or f"sim2real{tag}0"


def _create_vpc_stack(ctx, num_sg: int = 1) -> dict:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-os-vpc-")}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.91.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-os-subnet-")}]}],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"subnet {subnet_id}", lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_ids = []
    for i in range(num_sg):
        sg = ec2.create_security_group(
            GroupName=ctx.unique_name(f"sim2real-os-sg{i}-"),
            Description="sim2real opensearch behavioral test sg",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]
        ctx.on_cleanup(
            lambda sg_id=sg_id: _delete_net(ec2, vpc_id, f"sg {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id))
        )
        sg_ids.append(sg_id)

    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_ids": sg_ids}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_domain_active(ctx, name: str, timeout_s: float = 1500.0, interval_s: float = 2.0) -> dict:
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        # CreateVpcEndpoint refuses a domain whose DomainProcessingStatus is still Creating.
        settled = last.get("DomainProcessingStatus", "Active") == "Active"
        if last.get("Created") and not last.get("Processing") and settled:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={last})")


def _wait_endpoint_status(ctx, endpoint_id: str, terminal_statuses: set, timeout_s: float = 600.0, interval_s: float = 2.0) -> dict:
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
        last = resp["VpcEndpoints"][0]
        if last.get("Status") in terminal_statuses:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"vpc endpoint {endpoint_id} to reach {terminal_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"vpc endpoint {endpoint_id} never reached {terminal_statuses} (last={last})")


# The domain and its VPC endpoint delete asynchronously and keep requester-managed ENIs in the
# subnet meanwhile, so network deletes fail with DependencyViolation in that window. Each delete
# waits (bounded, shared per VPC) for the ENIs to go, retries, and raises naming the holders.
_NET_TEARDOWN_S = 840.0
_NET_DEADLINES: dict = {}


def _delete_net(ec2, vpc_id, label, delete) -> None:
    deadline = _NET_DEADLINES.setdefault(vpc_id, time.monotonic() + _NET_TEARDOWN_S)
    while _vpc_enis(ec2, vpc_id) and time.monotonic() < deadline:
        time.sleep(3)
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
        time.sleep(3)


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
