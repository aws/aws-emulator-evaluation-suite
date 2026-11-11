"""deploy-vpc-endpoint-cfn-policy-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpc-endpoint-cfn-policy-enforced"
GROUP = "deploy"
SERVICES = ["opensearch"]

# CloudFormation has no resource type for a classic (non-Serverless) OpenSearch VPC endpoint,
# so the domain and its network come from CloudFormation and the endpoint from CreateVpcEndpoint.
_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  DomainName:
    Type: String
  AccountId:
    Type: String
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.91.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Subnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.91.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: sim2real
          Value: behav
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real opensearch vpc endpoint test sg
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 10.91.0.0/16
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Domain:
    Type: AWS::OpenSearchService::Domain
    Properties:
      DomainName: !Ref DomainName
      EngineVersion: OpenSearch_2.11
      ClusterConfig:
        InstanceType: t3.small.search
        InstanceCount: 1
        DedicatedMasterEnabled: false
        ZoneAwarenessEnabled: false
      EBSOptions:
        EBSEnabled: true
        VolumeType: gp3
        VolumeSize: 10
      VPCOptions:
        SubnetIds: [!Ref Subnet]
        SecurityGroupIds: [!Ref SecurityGroup]
      Tags:
        - Key: sim2real:managed
          Value: "true"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AccountId}:root"
            Action: "es:*"
            Resource: !Sub "arn:aws:es:${AWS::Region}:${AccountId}:domain/${DomainName}/*"
Outputs:
  DomainArn:
    Value: !GetAtt Domain.Arn
  SubnetId:
    Value: !Ref Subnet
  SecurityGroupId:
    Value: !Ref SecurityGroup
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a CFN-deployed VPC domain, an authorized account is listed by ListVpcEndpointAccess, a
    revoke for a never-authorized account grants nothing, and revoking the real grant removes it."""
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # The sim2real- prefixes keep an orphaned domain or stack discoverable by name.
    domain_name = ctx.unique_name("sim2real-behav-")[:28].rstrip("-") or "sim2real-behav-fallback"
    stack_name = ctx.unique_name("sim2real-behav-osvpce-")

    def _cleanup_stack():
        cfn.delete_stack(StackName=stack_name)
        status = _wait_stack_terminal(cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=1700, interval_s=2)
        assert status == "DELETE_COMPLETE", f"stack {stack_name} ended in {status} during teardown"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "DomainName", "ParameterValue": domain_name},
            {"ParameterKey": "AccountId", "ParameterValue": account_id},
        ],
        OnFailure="DELETE",
    )

    ctx.on_cleanup(_cleanup_stack)

    final_status = _wait_stack_terminal(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=2700)
    assert final_status == "CREATE_COMPLETE", f"stack ended in {final_status}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    domain_arn = outputs["DomainArn"]
    subnet_id = outputs["SubnetId"]
    sg_id = outputs["SecurityGroupId"]

    _wait_domain_active(osc, domain_name, timeout_s=1800)

    ep = osc.create_vpc_endpoint(
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )["VpcEndpoint"]
    vpc_endpoint_id = ep["VpcEndpointId"]

    def _cleanup_endpoint():
        try:
            osc.delete_vpc_endpoint(VpcEndpointId=vpc_endpoint_id)
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(exc) != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_endpoint)

    _wait_endpoint_active(osc, vpc_endpoint_id, timeout_s=900)

    # --- positive: authorize the real account, confirm it is listed ---
    auth_resp = osc.authorize_vpc_endpoint_access(DomainName=domain_name, Account=account_id)
    authorized_principal = auth_resp["AuthorizedPrincipal"]["Principal"]
    assert authorized_principal == f"arn:aws:iam::{account_id}:root" or authorized_principal == account_id, (
        f"expected principal to be account {account_id} (root ARN or bare id), got {authorized_principal!r}"
    )

    listed = osc.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
    assert any(account_id in p["Principal"] for p in listed), listed

    # --- negative: revoking access for an account that was NEVER authorized has no effect ---
    # AWS treats a revoke for a never-authorized principal as a successful no-op; the invariant
    # is that the account never gains a grant, which the independent read below proves.
    never_authorized_account = "111111111111" if account_id != "111111111111" else "222222222222"
    try:
        osc.revoke_vpc_endpoint_access(DomainName=domain_name, Account=never_authorized_account)
        code = message = None
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    assert code in (None, "ResourceNotFoundException"), (
        f"expected RevokeVpcEndpointAccess for a never-authorized account to either no-op "
        f"(None) or raise ResourceNotFoundException, got {code!r}"
    )
    if code is not None:
        assert message == (
            "Either the domain doesn't exist, it doesn't support creation of VPC endpoints, or you "
            "don't have permission to create a VPC endpoint for the domain."
        ), f"RevokeVpcEndpointAccess ResourceNotFoundException message {message!r}"

    # the real, authorized account is still listed -- the never-authorized revoke had no effect
    listed_after_bad_revoke = osc.list_vpc_endpoint_access(DomainName=domain_name)[
        "AuthorizedPrincipalList"
    ]
    assert any(account_id in p["Principal"] for p in listed_after_bad_revoke), (
        f"authorized account {account_id} missing from listing after the rejected revoke: "
        f"{listed_after_bad_revoke}"
    )
    assert not any(never_authorized_account in p["Principal"] for p in listed_after_bad_revoke), (
        f"never-authorized account {never_authorized_account} appeared in listing after its "
        f"rejected revoke: {listed_after_bad_revoke}"
    )

    # --- now revoke the real grant and confirm it disappears (observable consequence) ---
    osc.revoke_vpc_endpoint_access(DomainName=domain_name, Account=account_id)
    _wait_until_absent(osc, domain_name, account_id, timeout_s=120)


def _error_code_from_exc(exc):
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _wait_stack_terminal(cfn, stack_name, ok_statuses, timeout_s=2700.0, interval_s=30.0):
    terminal_bad = {
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
    }
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception as exc:  # noqa: BLE001
            if "does not exist" in str(exc) and "DELETE_COMPLETE" in ok_statuses:
                return "DELETE_COMPLETE"
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status in ok_statuses or status in terminal_bad:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses} within {timeout_s}s")


def _wait_domain_active(osc, domain_name, timeout_s=1800.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last["Processing"] is False:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became Active within {timeout_s}s: {last}")


def _wait_endpoint_active(osc, vpc_endpoint_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = osc.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
        if resp.get("VpcEndpointErrors"):
            raise AssertionError(f"vpc endpoint error: {resp['VpcEndpointErrors']}")
        last = resp["VpcEndpoints"][0]["Status"]
        if last == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"vpc endpoint {vpc_endpoint_id} never became ACTIVE: last={last}")


def _wait_until_absent(osc, domain_name, account_id, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listed = osc.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
        if not any(account_id in p["Principal"] for p in listed):
            return
        time.sleep(interval_s)
    raise AssertionError(f"account {account_id} still listed as authorized after revoke")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
