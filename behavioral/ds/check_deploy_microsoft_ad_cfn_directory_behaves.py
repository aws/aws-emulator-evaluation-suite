"""deploy-microsoft-ad-cfn-directory-behaves."""
from __future__ import annotations

import itertools

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "deploy-microsoft-ad-cfn-directory-behaves"
GROUP = "deploy"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!2024Aa"
_RESET_PASSWORD = "Sim2Real!2025Bb"

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainName:
    Type: String
  AdminPassword:
    Type: String
    NoEcho: true
  VpcId:
    Type: AWS::EC2::VPC::Id
  SubnetId1:
    Type: AWS::EC2::Subnet::Id
  SubnetId2:
    Type: AWS::EC2::Subnet::Id
Resources:
  Directory:
    Type: AWS::DirectoryService::MicrosoftAD
    Properties:
      Name: !Ref DomainName
      Password: !Ref AdminPassword
      Edition: Standard
      VpcSettings:
        VpcId: !Ref VpcId
        SubnetIds:
          - !Ref SubnetId1
          - !Ref SubnetId2
Outputs:
  DirectoryId:
    Value: !Ref Directory
""".strip()


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::DirectoryService::MicrosoftAD stack yields an Active directory that accepts an Admin password
    reset and rejects one for a nonexistent user with UserDoesNotExistException and AWS's exact message."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    domain_name = f"{ctx.unique_name('sim2real-cfnad-')}.example.com"
    cfn = ctx.client("cloudformation")

    stack_name = directory_id = None
    attempted_pairs: list[tuple[str, str]] = []
    # DS rejects some AZs for Managed AD as capacity-constrained, so try each subnet pair.
    for pair in itertools.combinations(subnet_ids, 2):
        attempted_pairs.append(pair)
        try:
            stack_name, directory_id = _create_directory_stack(ctx, cfn, vpc_id, pair, domain_name)
            break
        except _AzCapacityConstrained:
            continue
    if directory_id is None:
        raise AssertionError(
            f"DS rejected every subnet pair tried for {domain_name!r} in VPC {vpc_id}: {attempted_pairs}"
        )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    ds = ctx.client("ds")
    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc["Stage"] == "Active", f"CFN-created directory stage is {desc['Stage']!r}, expected Active"

    # Positive control: the directory actually accepts administrative operations.
    ds.reset_user_password(DirectoryId=directory_id, UserName="Admin", NewPassword=_RESET_PASSWORD)

    # Negative: resetting a nonexistent user is rejected, and does not affect the admin account.
    code, message, request_id = _error(
        lambda: ds.reset_user_password(
            DirectoryId=directory_id, UserName="sim2real-no-such-user", NewPassword=_RESET_PASSWORD
        )
    )
    assert code == "UserDoesNotExistException", f"expected UserDoesNotExistException, got {code!r}"
    assert message == f"User: sim2real-no-such-user does not exist. : RequestId: {request_id}", (
        f"unexpected UserDoesNotExistException message: {message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", ""), err.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


class _AzCapacityConstrained(Exception):
    """Raised when DS rejects a specific subnet pair as AZ-capacity-constrained, not as a defect."""


def _create_directory_stack(ctx, cfn, vpc_id: str, subnet_pair: tuple[str, str], domain_name: str):
    stack_name = ctx.unique_name("sim2real-ds-cfn-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "DomainName", "ParameterValue": domain_name},
            {"ParameterKey": "AdminPassword", "ParameterValue": _PASSWORD},
            {"ParameterKey": "VpcId", "ParameterValue": vpc_id},
            {"ParameterKey": "SubnetId1", "ParameterValue": subnet_pair[0]},
            {"ParameterKey": "SubnetId2", "ParameterValue": subnet_pair[1]},
        ],
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 2700}
        )
    except Exception as err:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', e['ResourceStatus'])}"
            for e in events
            if e["ResourceStatus"].endswith("_FAILED")
        ]
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )
        if any("capacity constrained" in r for r in reasons):
            raise _AzCapacityConstrained(f"subnets {subnet_pair} rejected: {reasons}") from err
        raise AssertionError(f"stack {stack_name} failed to create: {err}; reasons={reasons}") from err

    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"unexpected stack status {status}"
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    directory_id = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "DirectoryId")
    return stack_name, directory_id


def _default_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())[:4]

    name = ctx.unique_name("sim2real-ds-cfn-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:4]
    if len(azs) < 2:
        raise AssertionError("region does not offer 2+ availability zones required by DS")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
    return vpc_id, subnet_ids


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    # Bounded by the 1800 s cleanup budget; a stack still deleting then raises WaiterError.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 870}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
