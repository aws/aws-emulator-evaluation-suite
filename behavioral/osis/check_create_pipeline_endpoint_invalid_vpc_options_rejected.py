"""create-pipeline-endpoint-invalid-vpc-options-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-endpoint-invalid-vpc-options-rejected"
GROUP = "error-semantics"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePipelineEndpoint rejects VpcOptions whose subnet/security group ids violate the id
    pattern with ValidationException, while a control with real ids against the same fake pipeline
    fails on the pipeline lookup instead, and none of the three calls leaves an endpoint behind."""
    osis = ctx.client("osis")
    sts = ctx.client("sts")
    ec2 = ctx.client("ec2")
    account_id = sts.get_caller_identity()["Account"]
    fake_pipeline_arn = (
        f"arn:aws:osis:{ctx.region}:{account_id}:pipeline/{ctx.unique_name('sim2real-behav-')}"
    )

    malformed = _client_error(
        lambda: osis.create_pipeline_endpoint(
            PipelineArn=fake_pipeline_arn,
            VpcOptions={
                "SubnetIds": ["not-a-valid-subnet-id"],
                "SecurityGroupIds": ["not-a-valid-sg-id"],
            },
        )
    )
    assert malformed.get("Code") == "ValidationException", (
        f"expected ValidationException, got {malformed.get('Code')!r}"
    )
    expected = (
        "2 validation errors detected: Value '[not-a-valid-sg-id]' at 'vpcOptions.securityGroupIds' "
        "failed to satisfy constraint: Member must satisfy constraint: [Member must have length less "
        "than or equal to 20, Member must have length greater than or equal to 11, Member must "
        "satisfy regular expression pattern: sg-\\w{8}(\\w{9})?.*]; Value '[not-a-valid-subnet-id]' at "
        "'vpcOptions.subnetIds' failed to satisfy constraint: Member must satisfy constraint: [Member "
        "must have length less than or equal to 24, Member must have length greater than or equal to "
        "15, Member must satisfy regular expression pattern: subnet-\\w{8}(\\w{9})?.*]"
    )
    assert malformed.get("Message") == expected, (
        f"expected message {expected!r}, got {malformed.get('Message')!r}"
    )

    subnet_id, sg_id = _create_control_vpc_resources(ctx, ec2)

    control = _client_error(
        lambda: osis.create_pipeline_endpoint(
            PipelineArn=fake_pipeline_arn,
            VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        )
    )
    assert control.get("Code") == "ResourceNotFoundException", (
        "a real subnet/security group on the same fake pipeline must clear VpcOptions "
        f"validation and fail on the pipeline lookup instead, got {control.get('Code')!r}"
    )
    expected_control = "The pipeline could not be found"
    assert control.get("Message") == expected_control, (
        f"expected message {expected_control!r}, got {control.get('Message')!r}"
    )

    endpoints = osis.list_pipeline_endpoints().get("PipelineEndpoints", [])
    assert not any(e.get("PipelineArn") == fake_pipeline_arn for e in endpoints), (
        "none of the rejected create_pipeline_endpoint calls may have created an endpoint"
    )


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_control_vpc_resources(ctx, ec2) -> tuple[str, str]:
    """A VPC, subnet and security group this check owns, each torn down after it."""
    name = ctx.unique_name("sim2real-osis-behav-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_best_effort(ec2, vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.0.0/25",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]

    sg_name = ctx.unique_name("sim2real-osis-behav-")
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=sg_name,
        Description="sim2real audit control security group",
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_id, sg_id


def _delete_vpc_best_effort(ec2, vpc_id: str) -> None:
    for subnet in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet["SubnetId"])
    _delete_net(ec2, "delete_vpc", VpcId=vpc_id)


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that would leak the
# VPC. So wait (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same
# window, and raise a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 900s cleanup budget.
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
