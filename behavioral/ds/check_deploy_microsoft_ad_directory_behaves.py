"""deploy-microsoft-ad-directory-behaves."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "deploy-microsoft-ad-directory-behaves"
GROUP = "deploy"
SERVICES = ["ds"]

_STRONG_PASSWORD = "Sim2Real-Test-Passw0rd1!"
_RESET_PASSWORD = "Sim2Real-Reset-Pwd1!"
_POST_DELETE_PASSWORD = "Sim2Real-Reset-Pwd2!"

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcId:
    Type: String
  Subnet1:
    Type: String
  Subnet2:
    Type: String
  DirectoryName:
    Type: String
  DirectoryPassword:
    Type: String
    NoEcho: true
Resources:
  Directory:
    Type: AWS::DirectoryService::MicrosoftAD
    Properties:
      Name: !Ref DirectoryName
      Password: !Ref DirectoryPassword
      Edition: Standard
      VpcSettings:
        VpcId: !Ref VpcId
        SubnetIds:
          - !Ref Subnet1
          - !Ref Subnet2
Outputs:
  DirectoryId:
    Value: !Ref Directory
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed MicrosoftAD directory reaches Active and is usable (ResetUserPassword, AddIpRoutes).
    Deleting the stack must actually remove the directory: later calls get EntityDoesNotExistException.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html"""
    vpc_id, subnet_ids, vpc_cidr_blocks = _pick_default_vpc_subnets(ctx)

    base = ctx.unique_name("sim2realdscfn")
    domain_name = f"{base}.example.com"

    stack_name, outputs = _deploy_cfn_stack(
        ctx,
        _TEMPLATE,
        {
            "VpcId": vpc_id,
            "Subnet1": subnet_ids[0],
            "Subnet2": subnet_ids[1],
            "DirectoryName": domain_name,
            "DirectoryPassword": _STRONG_PASSWORD,
        },
    )
    directory_id = outputs["DirectoryId"]
    ds = ctx.client("ds")
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}])

    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc["Stage"] == "Active", f"expected stage Active, got {desc['Stage']!r}"
    assert desc["Name"] == domain_name, f"expected name {domain_name!r}, got {desc['Name']!r}"
    assert desc["Type"] == "MicrosoftAD", f"expected type MicrosoftAD, got {desc['Type']!r}"
    assert set(desc["VpcSettings"]["SubnetIds"]) == set(subnet_ids), (
        f"expected subnets {set(subnet_ids)}, got {set(desc['VpcSettings']['SubnetIds'])}"
    )
    assert desc["VpcSettings"]["VpcId"] == vpc_id, (
        f"expected vpc {vpc_id!r}, got {desc['VpcSettings']['VpcId']!r}"
    )

    # The deployed directory must actually work, not merely report CREATE_COMPLETE.
    ds.reset_user_password(
        DirectoryId=directory_id, UserName="Admin", NewPassword=_RESET_PASSWORD
    )

    # AddIpRoutes rejects any range already routed by the VPC's route tables (a Transit Gateway
    # or peering route can cover all of RFC1918), so the route under test avoids every routed CIDR.
    ec2 = ctx.client("ec2")
    routed_cidrs = list(vpc_cidr_blocks)
    for rt in ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]:
        for r in rt.get("Routes", []):
            cidr = r.get("DestinationCidrBlock")
            # The 0.0.0.0/0 default route overlaps everything and does not block AddIpRoutes.
            if cidr and ipaddress.ip_network(cidr).prefixlen > 0:
                routed_cidrs.append(cidr)
    route_cidr = _pick_non_overlapping_route_cidr(routed_cidrs)

    ds.add_ip_routes(
        DirectoryId=directory_id,
        IpRoutes=[{"CidrIp": route_cidr, "Description": "sim2real-cfn-route"}],
    )
    routes = _poll_until(
        lambda: ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"],
        lambda rs: any(r["CidrIp"] == route_cidr and r["IpRouteStatusMsg"] == "Added" for r in rs),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert any(r["CidrIp"] == route_cidr and r["IpRouteStatusMsg"] == "Added" for r in routes), (
        f"expected route {route_cidr} in state Added, got {routes!r}"
    )

    # Deletion runs in the body: cleanup's 60s budget is far shorter than a directory's deletion time.
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(cfn, stack_name, timeout_s=3600.0)

    stage = _wait_for_directory_stage(ds, directory_id, {"Deleted"}, timeout_s=1800.0, interval_s=20.0)
    assert stage == "Deleted", f"expected directory to reach Deleted, got {stage!r}"

    err = _client_error(
        lambda: ds.reset_user_password(
            DirectoryId=directory_id, UserName="Admin", NewPassword=_POST_DELETE_PASSWORD
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException against the deleted directory, got {code!r}"
    )
    expected_message = (
        f"Directory: '{directory_id}' does not exist. : RequestId: {err.response['ResponseMetadata']['RequestId']}"
    )
    message = err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _pick_default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network available in this account/region for the CFN deployment")
    vpc = vpcs[0]
    vpc_id = vpc["VpcId"]
    cidr_blocks = [a["CidrBlock"] for a in vpc.get("CidrBlockAssociationSet", []) if a.get("CidrBlock")]
    if not cidr_blocks:
        cidr_blocks = [vpc["CidrBlock"]]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in at least 2 availability zones")
    subnet_ids = list(by_az.values())[:2]
    return vpc_id, subnet_ids, cidr_blocks


def _pick_non_overlapping_route_cidr(routed_cidr_blocks) -> str:
    routed_nets = [ipaddress.ip_network(c) for c in routed_cidr_blocks]
    # IANA documentation/example ranges (RFC 5737) -- reserved so they are never a
    # real network's CIDR, and therefore never already routed in any real VPC.
    for candidate in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"):
        candidate_net = ipaddress.ip_network(candidate)
        if not any(candidate_net.overlaps(v) for v in routed_nets):
            return candidate
    raise AssertionError(f"no candidate route CIDR avoids overlap with routed CIDR(s) {routed_cidr_blocks}")


def _deploy_cfn_stack(ctx, template_body, parameters, timeout_s=3600.0):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ds-cfn-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_best_effort(cfn, stack_name))
    deadline = time.monotonic() + timeout_s
    status = None
    failure_statuses = (
        "CREATE_FAILED",
        "ROLLBACK_IN_PROGRESS",
        "ROLLBACK_FAILED",
        "ROLLBACK_COMPLETE",
        "DELETE_IN_PROGRESS",
        "DELETE_FAILED",
        "DELETE_COMPLETE",
    )
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as err:
            if "does not exist" in str(err):
                raise AssertionError(
                    f"stack {stack_name} failed to create and was already removed by "
                    f"OnFailure=DELETE before its failure reason could be read"
                ) from err
            raise
        status = stacks[0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
            return stack_name, outputs
        if status in failure_statuses:
            reason = _stack_failure_reason(cfn, stack_name)
            raise AssertionError(f"stack {stack_name} entered {status}: {reason}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s (last={status})")


def _stack_failure_reason(cfn, stack_name) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except ClientError:
        return "no failure reason available (stack events not retrievable)"
    for event in events:
        if event.get("ResourceStatus", "").endswith("FAILED") and event.get("ResourceStatusReason"):
            return f"{event['LogicalResourceId']}: {event['ResourceStatusReason']}"
    return "no FAILED resource event found in stack history"


def _delete_stack_best_effort(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _wait_for_stack_deleted(cfn, stack_name, timeout_s=3600.0, interval_s=15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as err:
            if "does not exist" in str(err):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(
                f"stack {stack_name} entered DELETE_FAILED: {_stack_failure_reason(cfn, stack_name)}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s (last={status})"
            )
        time.sleep(interval_s)


def _wait_for_directory_stage(ds, directory_id, target_stages, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException" and "Deleted" in target_stages:
                return "Deleted"
            raise
        if descs:
            stage = descs[0]["Stage"]
            if stage in target_stages:
                return stage
            if stage == "Failed":
                raise AssertionError(f"directory {directory_id} entered Failed while waiting for {target_stages}")
        elif "Deleted" in target_stages:
            return "Deleted"
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s")
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return the ClientError it raises. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
