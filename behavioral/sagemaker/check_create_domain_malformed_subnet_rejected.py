"""create-domain-malformed-subnet-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-domain-malformed-subnet-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with a malformed VPC subnet identifier is rejected rather than creating a broken domain."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    vpc_id, subnet_id = _get_or_create_vpc_subnet(ctx)

    bad_domain_name = ctx.unique_name("sim2real-behav-baddom-")
    code, message = _error(lambda: sm.create_domain(
        DomainName=bad_domain_name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        SubnetIds=["not-a-real-subnet-id"],
        VpcId="not-a-real-vpc-id",
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "2 validation errors detected: Value 'not-a-real-vpc-id' at 'vpcId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: vpc-[a-z0-9]{8,}; Value "
        "'[not-a-real-subnet-id]' at 'subnetIds' failed to satisfy constraint: Member must satisfy "
        "constraint: [Member must have length less than or equal to 32, Member must have length "
        "greater than or equal to 0, Member must satisfy regular expression pattern: "
        "subnet-[a-z0-9]{8,}]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no domain with this name was persisted
    domains = sm.list_domains()["Domains"]
    assert not any(d["DomainName"] == bad_domain_name for d in domains), (
        f"a domain named {bad_domain_name!r} was created despite the malformed subnet id"
    )

    # positive control: a real VPC/subnet is accepted
    good_domain_name = ctx.unique_name("sim2real-behav-gooddom-")
    resp = _create_domain_with_role_propagation_retry(
        sm,
        DomainName=good_domain_name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        SubnetIds=[subnet_id],
        VpcId=vpc_id,
        Tags=[{"Key": "Name", "Value": good_domain_name}],
    )
    domain_id = resp["DomainId"]
    ctx.on_cleanup(lambda: _cleanup_domain(sm, domain_id))
    assert resp["DomainArn"].endswith(domain_id), (
        f"expected DomainArn to end with {domain_id!r}, got {resp['DomainArn']!r}"
    )

    # terminal read: independent of the mutating CreateDomain call, at the destination
    desc = _wait_for_domain_status(sm, domain_id, "InService")
    assert desc["DomainName"] == good_domain_name, (
        f"expected DomainName {good_domain_name!r} on independent read, got {desc['DomainName']!r}"
    )
    assert desc["Status"] == "InService", f"expected InService, got {desc['Status']!r}"


# ===== helpers =====

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _cleanup_domain(sm, domain_id):
    # Let a Pending domain settle before deleting it; an already-deleted domain is done.
    deadline = time.monotonic() + 900.0
    while True:
        try:
            status = sm.describe_domain(DomainId=domain_id)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if status != "Pending" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    try:
        sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _wait_for_domain_status(sm, domain_id, want, timeout_s=900.0, interval_s=15.0):
    """Poll describe_domain (an independent read) until it leaves the transient
    Pending state. Raises rather than returning a stale/transient value so a caller
    can never assert against a status the domain hasn't actually reached."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = sm.describe_domain(DomainId=domain_id)
        status = desc["Status"]
        if status == want:
            return desc
        if status not in ("Pending", want):
            raise AssertionError(f"domain {domain_id} entered unexpected status {status!r} while waiting for {want!r}")
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_id} did not reach {want!r} within {timeout_s}s")


def _create_domain_with_role_propagation_retry(sm, timeout_s=90.0, interval_s=5.0, **kwargs):
    """CreateDomain validates that ExecutionRole is assumable; IAM role trust-policy
    propagation can lag get_role visibility by several seconds. Retry the actual call
    (bounded, with a stated reason) instead of sleeping blindly beforehand."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_domain(**kwargs)
        except ClientError as exc:
            error = exc.response["Error"]
            if time.monotonic() >= deadline or "role" not in error.get("Message", "").lower():
                raise
            time.sleep(interval_s)


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-smrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


def _get_or_create_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    # No usable shared network in this account/region — create the prerequisite rather
    # than depending on an ambient one that a freshly provisioned account won't have.
    vpc_name = ctx.unique_name("sim2real-behav-smvpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.219.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_name = ctx.unique_name("sim2real-behav-smsubnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.219.0.0/25",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


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
