"""deploy-private-dns-namespace-hosted-zone-delete-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-private-dns-namespace-hosted-zone-delete-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53", "servicediscovery"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_DELETE_BUDGET_S = 600.0


def _template(ns_name: str, svc_name: str, instance_id: str) -> str:
    return json.dumps({
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.91.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                },
            },
            "Namespace": {
                "Type": "AWS::ServiceDiscovery::PrivateDnsNamespace",
                "Properties": {"Name": ns_name, "Vpc": {"Ref": "Vpc"}},
            },
            "Service": {
                "Type": "AWS::ServiceDiscovery::Service",
                "Properties": {
                    "Name": svc_name,
                    "NamespaceId": {"Ref": "Namespace"},
                    "DnsConfig": {"DnsRecords": [{"Type": "A", "TTL": 60}]},
                },
            },
            "Instance": {
                "Type": "AWS::ServiceDiscovery::Instance",
                "Properties": {
                    "InstanceId": instance_id,
                    "ServiceId": {"Ref": "Service"},
                    "InstanceAttributes": {"AWS_INSTANCE_IPV4": "192.0.2.91"},
                },
            },
        },
        "Outputs": {"NamespaceRef": {"Value": {"Ref": "Namespace"}}},
    })


def _wait_stack(cf, stack_id: str, terminal=_TERMINAL, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id: str) -> None:
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def expect_error(fn, code: str, message: str) -> None:
    """Asserts fn() raises a ClientError with exactly (code, message); an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteHostedZone on the zone AWS Cloud Map created for a CloudFormation PrivateDnsNamespace
    is refused AccessDenied naming the zone and the owning namespace; the namespace keeps resolving
    through DiscoverInstances and GetHostedZone still answers the same, unchanged zone.
    """
    cfn = ctx.client("cloudformation")
    sd = ctx.client("servicediscovery")
    r53 = ctx.client("route53")

    ns_name = ctx.unique_name("sim2real-behav-cmown-") + ".example.com"
    svc_name = ctx.unique_name("sim2real-behav-cmownsvc-")
    instance_id = ctx.unique_name("sim2real-behav-cmowninst-")
    stack_name = ctx.unique_name("sim2real-behav-cfn-cmown-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(ns_name, svc_name, instance_id),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    namespace_id = outputs["NamespaceRef"]

    namespace = sd.get_namespace(Id=namespace_id)["Namespace"]
    namespace_arn = namespace["Arn"]
    zone_id = namespace["Properties"]["DnsProperties"]["HostedZoneId"]
    assert zone_id, f"GetNamespace carried no HostedZoneId: {namespace['Properties']!r}"

    discovered = _poll_until(
        lambda: sd.discover_instances(
            NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL"
        )["Instances"],
        lambda insts: any(i["InstanceId"] == instance_id for i in insts),
        timeout_s=90.0, interval_s=3.0,
        description=f"DiscoverInstances returning instance {instance_id!r}",
    )
    found = next(i for i in discovered if i["InstanceId"] == instance_id)
    assert found["Attributes"].get("AWS_INSTANCE_IPV4") == "192.0.2.91", (
        f"expected AWS_INSTANCE_IPV4=192.0.2.91 for instance {instance_id!r} via DiscoverInstances, "
        f"got {found['Attributes']!r}"
    )

    before = r53.get_hosted_zone(Id=zone_id)["HostedZone"]
    assert before["Id"] == f"/hostedzone/{zone_id}", (
        f"GetHostedZone Id {before['Id']!r} before the refused delete, expected /hostedzone/{zone_id}"
    )
    assert before["Name"] == f"{ns_name}.", (
        f"GetHostedZone Name {before['Name']!r} before the refused delete, expected {ns_name}."
    )

    _OWNED_BY_CLOUD_MAP = (
        "AccessDenied",
        f"The resource hostedzone/{zone_id} can only be managed through AWS Cloud Map ({namespace_arn})",
    )
    expect_error(lambda: r53.delete_hosted_zone(Id=zone_id), *_OWNED_BY_CLOUD_MAP)

    still_there = r53.get_hosted_zone(Id=zone_id)["HostedZone"]
    assert still_there["Id"] == f"/hostedzone/{zone_id}", (
        f"GetHostedZone Id after the refused delete is {still_there['Id']!r}, expected /hostedzone/{zone_id}"
    )
    assert still_there["Name"] == f"{ns_name}.", (
        f"GetHostedZone Name after the refused delete is {still_there['Name']!r}, expected {ns_name}."
    )

    rediscovered = _poll_until(
        lambda: sd.discover_instances(
            NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL"
        )["Instances"],
        lambda insts: any(i["InstanceId"] == instance_id for i in insts),
        timeout_s=90.0, interval_s=3.0,
        description=f"DiscoverInstances still returning instance {instance_id!r} after the refused delete",
    )
    still_found = next(i for i in rediscovered if i["InstanceId"] == instance_id)
    assert still_found["Attributes"].get("AWS_INSTANCE_IPV4") == "192.0.2.91", (
        f"expected AWS_INSTANCE_IPV4=192.0.2.91 for instance {instance_id!r} via DiscoverInstances "
        f"after the refused delete, got {still_found['Attributes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
