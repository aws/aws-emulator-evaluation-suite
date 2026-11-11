"""create-domain-malformed-vpc-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-malformed-vpc-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with SubnetIds outside the specified VpcId is accepted synchronously and the
    domain then lands in Status=Failed rather than InService, while a consistent VPC/subnet pairing
    (the positive control) reaches Pending/InService."""
    # Studio domain creation provisions an EFS file system and can take several minutes, even for
    # the positive control.
    ec2 = ctx.client("ec2")
    sm = ctx.client("sagemaker")

    # The "declared" VPC/subnet: the VpcId every create_domain call below states, and the
    # subnet the positive control actually uses. Created in-check rather than assumed from
    # an ambient default VPC, which a freshly provisioned account may not have.
    declared_vpc_id = ec2.create_vpc(
        CidrBlock="10.231.76.0/24",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-declared-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=declared_vpc_id)))

    declared_subnet_id = ec2.create_subnet(
        VpcId=declared_vpc_id,
        CidrBlock="10.231.76.0/25",
        TagSpecifications=[
            {
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-declared-subnet-")}],
            }
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=declared_subnet_id))
    )

    # A second, unrelated VPC+subnet used only to build the inconsistent pairing.
    other_vpc_id = ec2.create_vpc(
        CidrBlock="10.231.77.0/24",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mismatch-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=other_vpc_id)))

    other_subnet_id = ec2.create_subnet(
        VpcId=other_vpc_id,
        CidrBlock="10.231.77.0/25",
        TagSpecifications=[
            {
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mismatch-subnet-")}],
            }
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=other_subnet_id))
    )

    role_arn = _create_sagemaker_exec_role(ctx)

    # --- negative: SubnetIds belong to other_vpc, not the declared VpcId ---
    # Real AWS accepts this call (HTTP 200, Status=Pending) and rejects it later, during
    # async provisioning, once it resolves the subnet against the declared VPC. The bounded
    # poll below is that rejection's only observable surface; the create_domain response
    # itself is accepted.
    bad_domain_name = ctx.unique_name("sim2real-bad-domain-")
    bad_resp = sm.create_domain(
        DomainName=bad_domain_name,
        AuthMode="IAM",
        VpcId=declared_vpc_id,
        SubnetIds=[other_subnet_id],
        AppNetworkAccessType="VpcOnly",
        DefaultUserSettings={"ExecutionRole": role_arn},
    )
    bad_domain_id = bad_resp["DomainId"]
    ctx.on_cleanup(lambda: _delete_domain_best_effort(sm, bad_domain_id))

    bad_status, bad_reason = _poll_domain_terminal(sm, bad_domain_id, timeout_s=280.0, interval_s=15.0)
    assert bad_status == "Failed", (
        f"expected an internally inconsistent VPC config to fail asynchronously, "
        f"got terminal status {bad_status!r} (reason={bad_reason!r})"
    )
    assert bad_reason, "a Failed domain must carry a non-empty FailureReason"

    # effect absent: the domain never became usable
    domains = sm.list_domains()["Domains"]
    assert not any(
        d["DomainName"] == bad_domain_name and d["Status"] == "InService" for d in domains
    ), "an internally inconsistent VPC config reached InService"

    # --- positive control: a consistent VpcId/SubnetIds pairing succeeds ---
    good_domain_name = ctx.unique_name("sim2real-good-domain-")
    resp = sm.create_domain(
        DomainName=good_domain_name,
        AuthMode="IAM",
        VpcId=declared_vpc_id,
        SubnetIds=[declared_subnet_id],
        AppNetworkAccessType="VpcOnly",
        DefaultUserSettings={"ExecutionRole": role_arn},
    )
    domain_id = resp["DomainId"]
    ctx.on_cleanup(lambda: _delete_domain_best_effort(sm, domain_id))

    good_status, good_reason = _poll_domain_terminal(sm, domain_id, timeout_s=280.0, interval_s=15.0)
    assert good_status == "InService", (
        f"expected a consistent VPC config to provision successfully, got terminal status "
        f"{good_status!r} (reason={good_reason!r})"
    )
    described = sm.describe_domain(DomainId=domain_id)
    assert described["VpcId"] == declared_vpc_id, (
        f"expected persisted VpcId {declared_vpc_id!r}, got {described['VpcId']!r}"
    )
    assert described["SubnetIds"] == [declared_subnet_id], (
        f"expected persisted SubnetIds {[declared_subnet_id]!r}, got {described['SubnetIds']!r}"
    )


# ===== helpers =====
def _poll_domain_terminal(sm, domain_id: str, *, timeout_s: float, interval_s: float):
    """Poll DescribeDomain until Status leaves the transient "Pending" state. Returns
    (status, failure_reason); raises on timeout rather than returning the last-seen value."""
    deadline = time.monotonic() + timeout_s
    status, reason = None, None
    while time.monotonic() < deadline:
        described = sm.describe_domain(DomainId=domain_id)
        status = described["Status"]
        reason = described.get("FailureReason")
        if status != "Pending":
            return status, reason
        time.sleep(interval_s)
    raise AssertionError(
        f"domain {domain_id} still Pending after {timeout_s}s (no terminal status observed)"
    )


def _create_sagemaker_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    arn = resp["Role"]["Arn"]
    # IAM role visibility can lag its own create_role response by a few seconds; poll for it
    # rather than sleeping blind. Bounded retry, not an unconditional wait.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_role(RoleName=role_name)
            return arn
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_domain_best_effort(sm, domain_id: str) -> None:
    # DeleteDomain rejects a still-Pending domain with ResourceInUse: retry that to a deadline and
    # raise anything else. Returns once the delete is accepted, leaving the cleanup budget to the
    # subnet/VPC deletes that run next and retry through the domain's lingering ENIs.
    deadline = time.monotonic() + 300
    while True:
        try:
            sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_with_retry(fn, *, timeout_s: float = 120.0, interval_s: float = 10.0) -> None:
    # A subnet/VPC delete issued right after a DeleteDomain call can race that domain's ENI
    # teardown and fail with DependencyViolation; retry rather than leaking the VPC/subnet.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
