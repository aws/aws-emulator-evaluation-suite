"""create-domain-malformed-domain-name-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-malformed-domain-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateDomain with a DomainName violating the length/charset constraints is
    rejected with ValidationException rather than accepted verbatim."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    vpc_id, subnet_ids = _get_vpc_subnets(ctx, min_count=1)

    # DomainName pattern is `^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`, max 63 chars -
    # spaces and punctuation are not permitted.
    bad_name = "sim2real invalid!! domain name"
    code, message = _error(
        lambda: sm.create_domain(
            DomainName=bad_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            SubnetIds=subnet_ids,
            VpcId=vpc_id,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value 'sim2real invalid!! domain name' at 'domainName' failed "
        "to satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absence: no domain with that name was created.
    domains = sm.list_domains()["Domains"]
    assert not any(d["DomainName"] == bad_name for d in domains), (
        f"rejected DomainName {bad_name!r} nonetheless appeared in ListDomains: {domains!r}"
    )

    # Positive control: a well-formed DomainName is accepted and provisions.
    # The role/policy just created above can take a few seconds to propagate before
    # SageMaker can assume it, so retry the create call (bounded) instead of a fixed sleep.
    good_name = ctx.unique_name("sim2real-domain-")
    domain_id = _retry_result(
        lambda: sm.create_domain(
            DomainName=good_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            SubnetIds=subnet_ids,
            VpcId=vpc_id,
        )["DomainId"]
    )
    ctx.on_cleanup(lambda: _cleanup_domain(ctx, domain_id))
    _wait_domain_status(ctx, domain_id, "InService")
    desc = sm.describe_domain(DomainId=domain_id)
    assert desc["DomainName"] == good_name, f"expected DomainName {good_name!r}, got {desc['DomainName']!r}"


# ===== helpers =====

def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role["Arn"]


def _retry_result(fn: Callable[[], Any], attempts: int = 9, delay: float = 10.0) -> Any:
    """Retries a call bounded by attempts*delay, for IAM->SageMaker role propagation lag."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _get_vpc_subnets(ctx: Any, min_count: int = 1) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets[:min_count]]
        if len(subnet_ids) >= min_count:
            return vpc_id, subnet_ids
    vpc = ec2.create_vpc(
        CidrBlock="10.193.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(min_count):
        az = azs[i % len(azs)]["ZoneName"]
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.193.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _retry(fn: Callable[[], Any], attempts: int = 12, delay: float = 15.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _cleanup_domain(ctx: Any, domain_id: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_domain(DomainId=domain_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            sm.describe_domain(DomainId=domain_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"domain {domain_id} was not deleted within 900s")


def _wait_domain_status(ctx: Any, domain_id: str, want: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status == want:
            return
        if status in ("Failed", "Delete_Failed", "Update_Failed"):
            raise AssertionError(f"domain entered {status} while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"domain did not reach {want} within {timeout_s}s")


# Network teardown: a resource in this VPC deletes asynchronously and its ENIs linger, so
# DeleteSubnet/DeleteVpc first wait (bounded) for them and retry DependencyViolation in one window
# shared by all of the check's network deletes; the last failure raises naming the ENIs left.
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
