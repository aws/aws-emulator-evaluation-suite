"""deploy-http-namespace-service-via-cloudformation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-http-namespace-service-via-cloudformation"
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
Resources:
  Namespace:
    Type: AWS::ServiceDiscovery::HttpNamespace
    Properties:
      Name: !Ref NamespaceName
  Service:
    Type: AWS::ServiceDiscovery::Service
    Properties:
      Name: !Ref ServiceName
      NamespaceId: !GetAtt Namespace.Id
  Instance:
    Type: AWS::ServiceDiscovery::Instance
    Properties:
      InstanceId: !Ref InstanceId
      ServiceId: !GetAtt Service.Id
      InstanceAttributes:
        custom-attr: "cfn-value"
Outputs:
  NamespaceId:
    Value: !GetAtt Namespace.Id
  ServiceId:
    Value: !GetAtt Service.Id
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack with an HttpNamespace, a Service and an Instance reaches CREATE_COMPLETE,
    and DiscoverInstances on the deployed namespace and service returns that instance with its
    declared attribute value."""
    ns_name = ctx.unique_name("sim2real-behav-cfnhttp-")
    svc_name = ctx.unique_name("sim2real-behav-cfnsvc-")
    instance_id = ctx.unique_name("sim2real-behav-cfninst-")

    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        [
            {"ParameterKey": "NamespaceName", "ParameterValue": ns_name},
            {"ParameterKey": "ServiceName", "ParameterValue": svc_name},
            {"ParameterKey": "InstanceId", "ParameterValue": instance_id},
        ],
    )
    assert "NamespaceId" in outputs and "ServiceId" in outputs, (
        f"expected NamespaceId and ServiceId stack outputs, got {sorted(outputs)}"
    )

    sd = ctx.client("servicediscovery")
    instances = _poll_until(
        lambda: sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL")["Instances"],
        lambda insts: any(i["InstanceId"] == instance_id for i in insts),
        timeout_s=60.0,
        interval_s=3.0,
    )
    found = next(i for i in instances if i["InstanceId"] == instance_id)
    actual_attr = found["Attributes"].get("custom-attr")
    assert actual_attr == "cfn-value", (
        f"expected custom-attr='cfn-value' on the CFN-declared instance, got {actual_attr!r}"
    )


def _deploy_cfn(ctx, template_body: str, parameters: list[dict[str, str]]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

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
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert desc["StackStatus"] == "CREATE_COMPLETE", f"unexpected stack status: {desc['StackStatus']}"
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


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
