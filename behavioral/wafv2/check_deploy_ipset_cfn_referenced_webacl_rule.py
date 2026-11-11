"""deploy-ipset-cfn-referenced-webacl-rule."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-ipset-cfn-referenced-webacl-rule"
GROUP = "deploy"
SERVICES = ["wafv2"]

# RFC 5737 TEST-NET ranges -- safe, documentation-reserved, never routable.
_ADDRESSES = ["192.0.2.0/24", "198.51.100.0/24"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IPSet deployed via CloudFormation returns byte-identical addresses via
    GetIPSet, and a WebACL rule created afterward referencing the CFN-provisioned
    IPSet's ARN resolves to that same set."""
    wafv2 = ctx.client("wafv2")
    cfn = ctx.client("cloudformation")

    ipset_name = ctx.unique_name("sim2real-waf-ipset-")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  CfnIPSet:
    Type: AWS::WAFv2::IPSet
    Properties:
      Name: {ipset_name}
      Scope: REGIONAL
      IPAddressVersion: IPV4
      Addresses:
        - {_ADDRESSES[0]}
        - {_ADDRESSES[1]}
      Tags:
        - Key: Team
          Value: sim2real
Outputs:
  IPSetArn:
    Value: !GetAtt CfnIPSet.Arn
  IPSetId:
    Value: !GetAtt CfnIPSet.Id
"""
    outputs = _deploy_cfn(ctx, cfn, template)
    ipset_arn = outputs["IPSetArn"]
    ipset_id = outputs["IPSetId"]

    fetched = wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL", Id=ipset_id)
    assert fetched["IPSet"]["ARN"] == ipset_arn, (
        f"expected GetIPSet to echo the CFN-provisioned ARN {ipset_arn!r}, "
        f"got {fetched['IPSet']['ARN']!r}"
    )
    assert sorted(fetched["IPSet"]["Addresses"]) == sorted(_ADDRESSES), (
        f"expected GetIPSet Addresses to be byte-identical to the CFN template's "
        f"{sorted(_ADDRESSES)!r}, got {sorted(fetched['IPSet']['Addresses'])!r}"
    )

    webacl_name = ctx.unique_name("sim2real-waf-refwebacl-")
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": webacl_name,
        },
        Rules=[
            {
                "Name": "IPSetRefRule",
                "Priority": 0,
                "Action": {"Block": {}},
                "Statement": {"IPSetReferenceStatement": {"ARN": ipset_arn}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "IPSetRefRuleMetric",
                },
            }
        ],
        Tags=[{"Key": "Team", "Value": "sim2real"}],
    )
    webacl_id = created["Summary"]["Id"]
    lock_token = created["Summary"]["LockToken"]

    def _delete_webacl():
        try:
            wafv2.delete_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=lock_token)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    # Registered AFTER the CFN cleanup below runs (LIFO), so the WebACL that
    # references the IPSet is deleted first, then the CFN stack deletes the IPSet.
    ctx.on_cleanup(_delete_webacl)

    fetched_acl = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    rule = next(r for r in fetched_acl["WebACL"]["Rules"] if r["Name"] == "IPSetRefRule")
    actual_arn = rule["Statement"]["IPSetReferenceStatement"]["ARN"]
    assert actual_arn == ipset_arn, (
        f"expected GetWebACL to resolve the rule's IPSetReferenceStatement to the "
        f"CFN-provisioned IPSet ARN {ipset_arn!r}, got {actual_arn!r}"
    )


def _deploy_cfn(ctx, cfn, template_body):
    stack_name = ctx.unique_name("sim2real-wafcfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
