"""deploy-domain-cfn-presigned-url-works."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlsplit

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "deploy-domain-cfn-presigned-url-works"
GROUP = "deploy"
SERVICES = ["sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcIdParam:
    Type: AWS::EC2::VPC::Id
  SubnetIdParam:
    Type: AWS::EC2::Subnet::Id
  DomainNameParam:
    Type: String
  UserProfileNameParam:
    Type: String
  ExecutionRoleArnParam:
    Type: String
Resources:
  Domain:
    Type: AWS::SageMaker::Domain
    Properties:
      DomainName: !Ref DomainNameParam
      AuthMode: IAM
      VpcId: !Ref VpcIdParam
      SubnetIds:
        - !Ref SubnetIdParam
      DefaultUserSettings:
        ExecutionRole: !Ref ExecutionRoleArnParam
  UserProfile:
    Type: AWS::SageMaker::UserProfile
    Properties:
      DomainId: !GetAtt Domain.DomainId
      UserProfileName: !Ref UserProfileNameParam
      UserSettings:
        ExecutionRole: !Ref ExecutionRoleArnParam
Outputs:
  DomainId:
    Value: !GetAtt Domain.DomainId
  UserProfileNameOut:
    Value: !Ref UserProfileNameParam
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Domain + UserProfile deployed via a CloudFormation stack supports a real,
    working CreatePresignedDomainUrl call -- proving the deployed resource is
    functionally usable, not just CREATE_COMPLETE."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")

    vpc_id, subnet_id = _vpc_subnet(ctx, ec2)

    role_name = ctx.unique_name("sim2real-sm-domain-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    )

    stack_name = ctx.unique_name("sim2real-sm-domain-stack-")
    domain_name = ctx.unique_name("sim2real-domain-")
    user_profile_name = ctx.unique_name("sim2real-user-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "VpcIdParam", "ParameterValue": vpc_id},
            {"ParameterKey": "SubnetIdParam", "ParameterValue": subnet_id},
            {"ParameterKey": "DomainNameParam", "ParameterValue": domain_name},
            {"ParameterKey": "UserProfileNameParam", "ParameterValue": user_profile_name},
            {"ParameterKey": "ExecutionRoleArnParam", "ParameterValue": role_arn},
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    stack_status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=1200,
        interval_s=15,
    )
    if stack_status != "CREATE_COMPLETE":
        raise AssertionError(f"stack did not reach CREATE_COMPLETE, got {stack_status}")

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    domain_id = outputs["DomainId"]

    domain_status = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=600,
        interval_s=15,
    )
    assert domain_status == "InService", f"domain never reached InService: {domain_status}"

    resp = sm.create_presigned_domain_url(DomainId=domain_id, UserProfileName=user_profile_name)
    url = resp["AuthorizedUrl"]
    parsed = urlparse(url)
    assert not (p := ctx.published_url_mismatch(url, labels=("studio", ctx.region, "sagemaker"), path="/auth")), p
    assert parsed.query, "expected a query string (auth token) on the presigned domain URL"

    # The independent, destination-side proof the URL actually works: fetch it and
    # confirm the redirect chain lands on THIS domain's own Studio host, not a sign-in
    # challenge -- a stub target has no real per-domain host to redirect to. (A plain
    # 403 past that point is expected: AWS returns it for a correctly
    # authenticated hand-off into a domain/user with no provisioned Studio app/space,
    # so status is not part of the gate.)
    try:
        final_url, status = _fetch_final_url(ctx, url)
    except urllib.error.URLError as exc:
        raise AssertionError(f"no outbound network access to verify presigned URL redirect target: {exc}") from exc
    studio_label = f"studio-{domain_id}"
    final_labels = (urlsplit(final_url).hostname or "").split(".")
    assert final_labels[0] == studio_label and _same_zone(final_url, url), (
        "a presigned domain URL for a CFN-deployed Domain/UserProfile should redirect to this "
        f"domain's own Studio host ({studio_label}.<zone of the presigned host>), not a sign-in "
        f"challenge or an unrelated host: status={status} final_url={final_url[:200]}"
    )


def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's. A hand-off to a sign-in page
    on another host is not, and the domain is compared, never named."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _fetch_final_url(ctx, url: str, timeout: float = 15.0) -> tuple[str, int]:
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-behavioral-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.geturl(), resp.status
    except urllib.error.HTTPError as exc:
        return exc.geturl(), exc.code


def _vpc_subnet(ctx, ec2):
    """Adopt the account's default VPC/subnet if one exists; otherwise create a
    disposable VPC+subnet, so a freshly provisioned account (no default VPC) still
    passes."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.196.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-sm-domain-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.196.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-sm-domain-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return vpc_id, subnet_id


def _retry_delete(fn, attempts: int = 12, delay: float = 15.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _stack_status(cfn, stack_name):
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except Exception:
        return None


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" not in exc.response["Error"]["Message"]
        ):
            raise
        return
    _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("DELETE_COMPLETE", None),
        timeout_s=1200,
        interval_s=15,
    )


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
