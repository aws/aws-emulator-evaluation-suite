"""list-resource-telemetry-resource-type-filter-invariant."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-telemetry-resource-type-filter-invariant"
GROUP = "data-plane"
SERVICES = ["observabilityadmin"]

VPC_TYPE = "AWS::EC2::VPC"
INSTANCE_TYPE = "AWS::EC2::Instance"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """ListResourceTelemetry with a ResourceTypes filter returns only configurations of the
    requested types: with a VPC and an EC2 instance both present, each type-scoped query surfaces
    its own resource and excludes the other."""
    client = ctx.client("observabilityadmin")
    _ensure_slr(ctx)
    _ensure_telemetry_evaluation(ctx, client)

    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-obsadmin-filter-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.220.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.220.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    instance_id = _launch_standalone_instance(ctx, ec2, name, subnet_id)

    # Positive control: both resources must actually surface, unfiltered, before the filter
    # invariant means anything -- a target that never discovers either would pass the
    # exclusion checks below for the wrong reason (nothing to leak in the first place).
    vpc_cfgs = _wait_for_resource(client, VPC_TYPE, vpc_id)
    instance_cfgs = _wait_for_resource(client, INSTANCE_TYPE, instance_id)
    assert all(cfg["ResourceType"] == VPC_TYPE for cfg in vpc_cfgs), (
        f"ListResourceTelemetry(ResourceTypes=[{VPC_TYPE}]) returned a non-{VPC_TYPE} entry: "
        f"{[c['ResourceType'] for c in vpc_cfgs if c['ResourceType'] != VPC_TYPE]}"
    )
    assert all(cfg["ResourceType"] == INSTANCE_TYPE for cfg in instance_cfgs), (
        f"ListResourceTelemetry(ResourceTypes=[{INSTANCE_TYPE}]) returned a non-{INSTANCE_TYPE} "
        f"entry: {[c['ResourceType'] for c in instance_cfgs if c['ResourceType'] != INSTANCE_TYPE]}"
    )
    assert not any(cfg["ResourceIdentifier"] == instance_id for cfg in vpc_cfgs), (
        f"ListResourceTelemetry(ResourceTypes=[{VPC_TYPE}]) returned the EC2 instance "
        f"{instance_id} even though that resource exists only under {INSTANCE_TYPE}"
    )
    assert not any(cfg["ResourceIdentifier"] == vpc_id for cfg in instance_cfgs), (
        f"ListResourceTelemetry(ResourceTypes=[{INSTANCE_TYPE}]) returned the VPC {vpc_id} "
        f"even though that resource exists only under {VPC_TYPE}"
    )

    # Deterministic half: combining a real type filter with a ResourceIdentifierPrefix that
    # cannot match any real resource must yield an empty result regardless of what real
    # resources exist in the account.
    empty_page = client.list_resource_telemetry(
        ResourceTypes=[VPC_TYPE],
        ResourceIdentifierPrefix="sim2real-definitely-nonexistent-resource-zzz",
    )
    assert empty_page.get("TelemetryConfigurations", []) == [], (
        f"ListResourceTelemetry with an unmatchable ResourceIdentifierPrefix returned "
        f"{len(empty_page.get('TelemetryConfigurations', []))} entries, expected 0"
    )
    assert "NextToken" not in empty_page, (
        f"ListResourceTelemetry with an unmatchable ResourceIdentifierPrefix returned a "
        f"NextToken ({empty_page.get('NextToken')!r}) for what should be a single empty page"
    )


# ===== helpers =====
def _ensure_slr(ctx) -> None:
    """ObservabilityAdmin's telemetry evaluation runs under a service-linked role. It is a
    shared, idempotent, account-level resource, so it is created-or-adopted and NOT torn
    down."""
    iam = ctx.client("iam")
    role_name = "AWSServiceRoleForObservabilityAdmin"
    try:
        iam.create_service_linked_role(AWSServiceName="observabilityadmin.amazonaws.com")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "InvalidInput":
            raise
        iam.get_role(RoleName=role_name)


def _ensure_telemetry_evaluation(ctx, client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    # Telemetry evaluation is an account setting: one this check starts is stopped again.
    ctx.on_cleanup(lambda: _stop_telemetry_evaluation(client))
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # The current region is always implicit; passing it in `Regions` is invalid.
            client.start_telemetry_evaluation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = client.get_telemetry_evaluation_status()
        status = got.get("Status")
        if status == "RUNNING":
            return
        if status == "FAILED_START":
            raise AssertionError(f"telemetry evaluation failed to start: {got.get('FailureReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached RUNNING (last={status})")


def _image_id(ec2, ssm) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    try:
        return ssm.get_parameter(Name=param)["Parameter"]["Value"]
    except ClientError:
        imgs = sorted(
            ec2.describe_images(
                Owners=["amazon"],
                Filters=[
                    {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                    {"Name": "state", "Values": ["available"]},
                ],
            ).get("Images", []),
            key=lambda i: i.get("CreationDate", ""),
        )
        if not imgs:
            raise AssertionError("no Amazon Linux 2023 AMI available in this region")
        return imgs[-1]["ImageId"]


def _stop_telemetry_evaluation(client, timeout_s=300.0, interval_s=5.0):
    client.stop_telemetry_evaluation()
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = client.get_telemetry_evaluation_status().get("Status")
        if status in ("STOPPED", "FAILED_STOP"):
            assert status == "STOPPED", "telemetry evaluation failed to stop"
            return
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached STOPPED (last={status})")


def _launch_standalone_instance(ctx, ec2, name: str, subnet_id: str) -> str:
    ssm = ctx.client("ssm")
    resp = ec2.run_instances(
        ImageId=_image_id(ec2, ssm),
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    return instance_id


def _list_all(client, **params):
    results = []
    next_token = None
    for _ in range(50):  # bounded pagination walk
        page_params = dict(params, MaxResults=50)
        if next_token:
            page_params["NextToken"] = next_token
        page = client.list_resource_telemetry(**page_params)
        results.extend(page.get("TelemetryConfigurations", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return results


def _wait_for_resource(client, resource_type, resource_id, deadline_s=480.0, interval_s=15.0):
    deadline = time.monotonic() + deadline_s
    cfgs: list = []
    while time.monotonic() < deadline:
        cfgs = _list_all(client, ResourceTypes=[resource_type])
        if any(cfg.get("ResourceIdentifier") == resource_id for cfg in cfgs):
            return cfgs
        time.sleep(interval_s)
    seen = sorted({cfg.get("ResourceIdentifier") for cfg in cfgs})
    raise AssertionError(
        f"{resource_type} resource {resource_id!r} never appeared in ListResourceTelemetry "
        f"within {deadline_s}s (last seen identifiers: {seen})"
    )


def _safe(fn) -> None:
    """Teardown call: a resource that is already gone is fine; any other error raises."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "InvalidInstanceID.NotFound", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound",
        ):
            raise


# EC2 network teardown: a resource in this VPC deletes asynchronously and its ENIs can still hold the
# subnet / VPC, failing the delete with DependencyViolation. Wait for those ENIs and retry that code
# within one window shared by the check's network deletes, then raise naming the ENIs still attached.
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
