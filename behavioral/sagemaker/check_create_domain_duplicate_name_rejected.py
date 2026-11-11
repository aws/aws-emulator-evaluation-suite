"""create-domain-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-domain-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateDomain with an in-use DomainName fails with ResourceInUse and the exact message
    and only one domain is listed; after deletion DescribeDomain and UpdateDomain fail with
    ResourceNotFound and the identical CreateDomain call succeeds."""
    ec2 = ctx.client("ec2")
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")

    vpc_id, subnet_id = _vpc_and_subnet(ec2, ctx=ctx)
    role_arn = _create_sagemaker_role(ctx, iam)

    domain_name = ctx.unique_name("sim2real-domain-")

    def _create():
        return sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    created = _retry_role_propagation(_create)
    domain_id = created["DomainArn"].rsplit("/", 1)[-1]

    live_domain_id = [domain_id]
    ctx.on_cleanup(lambda: _delete_domain_if_present(sm, live_domain_id[0]))

    # (c) positive control: the original domain reaches InService.
    status = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert status == "InService", f"expected InService, domain ended in {status}"

    # Negative: a second CreateDomain with the same DomainName is rejected while the
    # original domain still holds that name.
    code, message = _error(_create)
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code}"
    expected = f"The Domain Name '{domain_name}' already exists in this account in this region."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: only the original domain exists under this name.
    matches = [d for d in _all_domains(sm) if d["DomainName"] == domain_name]
    assert len(matches) == 1, f"expected exactly one domain named {domain_name}, found {len(matches)}"

    # Restore: the conflict is the existing domain's state, not the name. Delete it,
    # prove it gone via an independent read, prove a mutation on the dead id also
    # fails, then the identical CreateDomain call must now succeed.
    sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})

    gone_code, gone_message = _poll_until_rejected(
        lambda: sm.describe_domain(DomainId=domain_id),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert gone_code == "ResourceNotFound", (
        f"expected DescribeDomain on the deleted domain to be ResourceNotFound, got {gone_code}"
    )
    expected_gone = f"Domain [{created['DomainArn']}] does not exist."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    dead_update_code, dead_update_message = _error(
        lambda: sm.update_domain(DomainId=domain_id, DefaultUserSettings={"ExecutionRole": role_arn})
    )
    assert dead_update_code == "ResourceNotFound", (
        f"expected UpdateDomain on a deleted domain to fail with ResourceNotFound, got {dead_update_code}"
    )
    expected_dead_update = f"Domain [{created['DomainArn']}] does not exist."
    assert dead_update_message == expected_dead_update, (
        f"expected message {expected_dead_update!r}, got {dead_update_message!r}"
    )

    recreated = _retry_name_release(_create)
    live_domain_id[0] = recreated["DomainArn"].rsplit("/", 1)[-1]

    restored_status = _poll_until(
        lambda: sm.describe_domain(DomainId=live_domain_id[0])["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert restored_status == "InService", (
        f"expected the identical CreateDomain call to succeed once the name was free, "
        f"domain ended in {restored_status}"
    )
    restored_matches = [d for d in _all_domains(sm) if d["DomainName"] == domain_name]
    assert len(restored_matches) == 1, (
        f"expected exactly one domain named {domain_name} after restore, found {len(restored_matches)}"
    )


def _all_domains(sm):
    """Every domain the account lists, across all pages."""
    return [d for page in sm.get_paginator("list_domains").paginate() for d in page["Domains"]]


def _error(fn):
    """Return the (code, message) of a call that must fail; raise if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until_rejected(fn, *, timeout_s: float, interval_s: float):
    """Poll toward an eventual rejection (the domain stays describable while it
    deletes); return its (code, message), raising if the call still succeeds at the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"call still succeeded after {timeout_s}s, last={last!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _vpc_and_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"VPC {vpc_id} has no subnets available to host a Domain")
    return vpc_id, subnets[0]["SubnetId"]


def _create_sagemaker_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-smrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _delete_domain_if_present(sm, domain_id):
    try:
        sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM's own eventual consistency: a role SageMaker just tried to assume may not
    yet be visible. Bounded retry, never an unconditional sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


def _retry_name_release(fn, timeout_s: float = 180.0, interval_s: float = 10.0):
    """After DeleteDomain, the name may take a moment to become reusable even once
    DescribeDomain already reports ResourceNotFound. Bounded retry, never a sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceInUse":
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("name release retry loop exited without a result")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
