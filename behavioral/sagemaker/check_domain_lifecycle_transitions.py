"""domain-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain reaches InService and DescribeDomain returns its ARN, name and VPC; after DeleteDomain,
    DescribeDomain and a repeated DeleteDomain both return ResourceNotFound with the exact message.
    """
    sm = ctx.client("sagemaker")
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    role_arn = _create_sagemaker_role(ctx, managed_policy_arns=["arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"])
    name = ctx.unique_name("sim2real-domain-")

    create_resp = sm.create_domain(
        DomainName=name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        SubnetIds=[subnet_id],
        VpcId=vpc_id,
        AppNetworkAccessType="PublicInternetOnly",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    domain_id = create_resp["DomainId"]
    domain_arn = create_resp["DomainArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
        )
    )

    status = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=1200,
        interval_s=20,
    )
    assert status == "InService", f"expected Domain Status=InService, got {status}"

    described = sm.describe_domain(DomainId=domain_id)
    assert described["DomainArn"] == domain_arn, f"expected DomainArn={domain_arn}, got {described['DomainArn']}"
    assert described["DomainName"] == name, f"expected DomainName={name}, got {described['DomainName']}"
    assert described["VpcId"] == vpc_id, f"expected VpcId={vpc_id}, got {described['VpcId']}"

    sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})

    code, message = _refusal_eventually(
        lambda: sm.describe_domain(DomainId=domain_id), timeout_s=900, interval_s=15
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected = f"Domain [arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}] does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    redelete_code, redelete_message = _error(
        lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    )
    assert redelete_code == "ResourceNotFound", (
        f"expected a mutation on the already-deleted domain to also fail with ResourceNotFound, got {redelete_code}"
    )
    expected = f"Domain [arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}] does not exist."
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _refusal_eventually(fn, *, timeout_s, interval_s):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as e:
            err = e.response["Error"]
            return err["Code"], err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED and "
        f"returned {result!r}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to attach a SageMaker Domain")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for a SageMaker Domain")
    return vpc_id, subnets[0]["SubnetId"]


def _create_sagemaker_role(ctx, managed_policy_arns=None):
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    attached = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)

    def _cleanup():
        for policy_arn in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
