"""deploy-private-dns-namespace-via-cloudformation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-private-dns-namespace-via-cloudformation"
GROUP = "deploy"
SERVICES = ["servicediscovery"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  NamespaceName:
    Type: String
  ServiceName:
    Type: String
  InstanceId:
    Type: String
  VpcId:
    Type: String
Resources:
  Namespace:
    Type: AWS::ServiceDiscovery::PrivateDnsNamespace
    Properties:
      Name: !Ref NamespaceName
      Vpc: !Ref VpcId
  Service:
    Type: AWS::ServiceDiscovery::Service
    Properties:
      Name: !Ref ServiceName
      NamespaceId: !GetAtt Namespace.Id
      DnsConfig:
        DnsRecords:
          - Type: A
            TTL: 60
  Instance:
    Type: AWS::ServiceDiscovery::Instance
    Properties:
      InstanceId: !Ref InstanceId
      ServiceId: !GetAtt Service.Id
      InstanceAttributes:
        AWS_INSTANCE_IPV4: "10.0.0.5"
Outputs:
  NamespaceId:
    Value: !GetAtt Namespace.Id
  ServiceId:
    Value: !GetAtt Service.Id
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack declaring a PrivateDnsNamespace with a child Service and Instance
    yields a namespace that resolves the instance via DiscoverInstances after CREATE_COMPLETE,
    not merely a stack that reached that status."""
    vpc_id = _default_vpc_id(ctx)

    ns_name = ctx.unique_name("sim2real-behav-cfnns-")
    svc_name = ctx.unique_name("sim2real-behav-cfnsvc-")
    instance_id = ctx.unique_name("sim2real-behav-cfninst-")

    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        [
            {"ParameterKey": "NamespaceName", "ParameterValue": ns_name},
            {"ParameterKey": "ServiceName", "ParameterValue": svc_name},
            {"ParameterKey": "InstanceId", "ParameterValue": instance_id},
            {"ParameterKey": "VpcId", "ParameterValue": vpc_id},
        ],
    )
    assert "NamespaceId" in outputs and "ServiceId" in outputs, (
        f"CFN stack outputs missing NamespaceId/ServiceId: {outputs!r}"
    )

    sd = ctx.client("servicediscovery")
    instances = _poll_until(
        lambda: sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL")["Instances"],
        lambda insts: any(i["InstanceId"] == instance_id for i in insts),
        timeout_s=90.0,
        interval_s=3.0,
    )
    found = next(i for i in instances if i["InstanceId"] == instance_id)
    actual_ip = found["Attributes"].get("AWS_INSTANCE_IPV4")
    assert actual_ip == "10.0.0.5", (
        f"expected AWS_INSTANCE_IPV4=10.0.0.5 for instance {instance_id!r} via DiscoverInstances, got {actual_ip!r}"
    )


# ===== helpers =====

def _default_vpc_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to attach a private DNS "
            "namespace to -- would close by creating/selecting any VPC to pass as VpcId"
        )
    return vpcs[0]["VpcId"]


def _deploy_cfn(ctx, template_body: str, parameters: list[dict[str, str]]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    sd = ctx.client("servicediscovery")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    state: dict[str, str | None] = {"namespace_id": None}

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )
        namespace_id = state["namespace_id"]
        if namespace_id:
            try:
                sd.get_namespace(Id=namespace_id)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NamespaceNotFound":
                    raise
            else:
                raise AssertionError(
                    f"namespace {namespace_id!r} still visible via GetNamespace after stack reached DELETE_COMPLETE"
                )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert desc["StackStatus"] == "CREATE_COMPLETE", f"unexpected stack status: {desc['StackStatus']}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    state["namespace_id"] = outputs.get("NamespaceId")
    return outputs


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
