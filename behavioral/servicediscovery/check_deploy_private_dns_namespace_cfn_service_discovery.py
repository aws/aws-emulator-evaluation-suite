"""deploy-private-dns-namespace-cfn-service-discovery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-private-dns-namespace-cfn-service-discovery"
GROUP = "deploy"
SERVICES = ["servicediscovery"]

_FAILURE_STACK_STATUSES = {
    "CREATE_FAILED",
    "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_FAILED",
    "ROLLBACK_COMPLETE",
    "DELETE_FAILED",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack deploying PrivateDnsNamespace + Service reaches CREATE_COMPLETE and the deployed service actually serves RegisterInstance/DiscoverInstances."""
    cf = ctx.client("cloudformation")
    sd = ctx.client("servicediscovery")
    vpc_id = _default_vpc_id(ctx)

    ns_name = ctx.unique_name("simparity-sd-cfn-") + ".local"
    svc_name = ctx.unique_name("simparity-sd-cfn-svc-")
    stack_name = ctx.unique_name("simparity-sd-stack-")
    instance_id = ctx.unique_name("simparity-sd-cfn-inst-")

    template = json.dumps(
        {
            "Parameters": {
                "VpcId": {"Type": "String"},
                "NamespaceName": {"Type": "String"},
                "ServiceNameParam": {"Type": "String"},
            },
            "Resources": {
                "Namespace": {
                    "Type": "AWS::ServiceDiscovery::PrivateDnsNamespace",
                    "Properties": {"Name": {"Ref": "NamespaceName"}, "Vpc": {"Ref": "VpcId"}},
                },
                "Service": {
                    "Type": "AWS::ServiceDiscovery::Service",
                    "Properties": {
                        "Name": {"Ref": "ServiceNameParam"},
                        "NamespaceId": {"Ref": "Namespace"},
                        "DnsConfig": {
                            "DnsRecords": [{"Type": "A", "TTL": 60}],
                            "RoutingPolicy": "MULTIVALUE",
                        },
                    },
                    "DependsOn": "Namespace",
                },
            },
            "Outputs": {
                "NamespaceId": {"Value": {"Ref": "Namespace"}},
                "ServiceId": {"Value": {"Ref": "Service"}},
            },
        }
    )

    state = {"service_id": None}

    def _cleanup_stack():
        if state["service_id"]:
            _deregister_instance_best_effort(sd, state["service_id"], instance_id)
        cf.delete_stack(StackName=stack_name)
        _wait_stack(cf, stack_name, {"DELETE_COMPLETE"}, timeout_s=600.0)

    cf.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "VpcId", "ParameterValue": vpc_id},
            {"ParameterKey": "NamespaceName", "ParameterValue": ns_name},
            {"ParameterKey": "ServiceNameParam", "ParameterValue": svc_name},
        ],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    ctx.on_cleanup(_cleanup_stack)

    stack = _wait_stack(cf, stack_name, {"CREATE_COMPLETE"}, timeout_s=600.0)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    service_id = outputs["ServiceId"]
    state["service_id"] = service_id

    reg_resp = sd.register_instance(
        ServiceId=service_id,
        InstanceId=instance_id,
        Attributes={"AWS_INSTANCE_IPV4": "192.0.2.20"},
    )
    _wait_operation(sd, reg_resp["OperationId"], timeout_s=120.0)

    found = _poll_discover_instances(sd, ns_name, svc_name, instance_id, expect_present=True)
    assert found is not None, f"instance {instance_id} never appeared via DiscoverInstances"
    assert found["Attributes"]["AWS_INSTANCE_IPV4"] == "192.0.2.20", (
        f"expected AWS_INSTANCE_IPV4=192.0.2.20, got {found['Attributes'].get('AWS_INSTANCE_IPV4')!r}"
    )

    dereg_resp = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
    _wait_operation(sd, dereg_resp["OperationId"], timeout_s=120.0)
    state["service_id"] = None  # already deregistered; nothing left for cleanup to undo on this front

    _poll_discover_instances(sd, ns_name, svc_name, instance_id, expect_present=False)


def _default_vpc_id(ctx):

    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to create a private DNS namespace"
        )
    return vpcs[0]["VpcId"]


def _wait_stack(cf, stack_name, target_statuses, timeout_s: float = 600.0, interval_s: float = 15.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = cf.describe_stacks(StackName=stack_name)
            stacks = resp.get("Stacks", [])
        except ClientError:
            stacks = []
        if not stacks:
            if "DELETE_COMPLETE" in target_statuses:
                return {}
            raise AssertionError(f"stack {stack_name} not found while waiting for {target_statuses}")
        stack = stacks[0]
        status = stack["StackStatus"]
        if status in target_statuses:
            return stack
        if status in _FAILURE_STACK_STATUSES and status not in target_statuses:
            raise AssertionError(f"stack {stack_name} entered {status} while waiting for {target_statuses}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _wait_operation(sd, operation_id, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        status = op["Status"]
        if status == "SUCCESS":
            return op
        if status == "FAIL":
            raise AssertionError(
                f"operation {operation_id} failed: {op.get('ErrorCode')} {op.get('ErrorMessage')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"operation {operation_id} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _deregister_instance_best_effort(sd, service_id, instance_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=120.0)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InstanceNotFound", "ServiceNotFound"):
            raise


def _poll_discover_instances(
    sd, ns_name, svc_name, instance_id, expect_present, timeout_s: float = 60.0, interval_s: float = 3.0
):
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name)
        match = next((i for i in resp["Instances"] if i["InstanceId"] == instance_id), None)
        if expect_present and match is not None:
            return match
        if not expect_present and match is None:
            return None
        if time.monotonic() >= deadline:
            if expect_present:
                raise AssertionError(f"instance {instance_id} never appeared in DiscoverInstances within {timeout_s}s")
            raise AssertionError(f"instance {instance_id} still appears in DiscoverInstances after {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
