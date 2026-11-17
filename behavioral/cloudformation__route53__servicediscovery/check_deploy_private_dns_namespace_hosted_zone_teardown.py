"""deploy-private-dns-namespace-hosted-zone-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-private-dns-namespace-hosted-zone-teardown"
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
                    "CidrBlock": "10.77.0.0/16",
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
                    "InstanceAttributes": {"AWS_INSTANCE_IPV4": "192.0.2.77"},
                },
            },
        },
        "Outputs": {
            "NamespaceRef": {"Value": {"Ref": "Namespace"}},
            "ServiceRef": {"Value": {"Ref": "Service"}},
        },
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


def _delete_stack_named(cf, name: str, stack_id: str | None) -> None:
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError", f"Stack with id {name} does not exist",
            ):
                return
            raise
    _delete_stack(cf, stack_id)


def expect_error(fn, code: str, message: str) -> None:
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


def _namespace_ids_by_name(sd, name: str) -> list[str]:
    return [
        n["Id"]
        for page in sd.get_paginator("list_namespaces").paginate(
            Filters=[{"Name": "NAME", "Values": [name], "Condition": "EQ"}]
        )
        for n in page.get("Namespaces", [])
    ]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A deployed PrivateDnsNamespace resolves its Service's Instance through DiscoverInstances and
    carries a real Route 53 HostedZoneId; DeleteStack then drops the namespace from GetNamespace and
    ListNamespaces and drops its hosted zone from Route 53, each with its exact not-found outcome.
    """
    cfn = ctx.client("cloudformation")
    sd = ctx.client("servicediscovery")
    r53 = ctx.client("route53")

    ns_name = ctx.unique_name("sim2real-behav-cfnpdns-") + ".example.com"
    svc_name = ctx.unique_name("sim2real-behav-cfnpdsvc-")
    instance_id = ctx.unique_name("sim2real-behav-cfnpdinst-")
    stack_name = ctx.unique_name("sim2real-behav-cfn-sdpdns-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(ns_name, svc_name, instance_id),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack_name, stack_id))

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    namespace_id = outputs["NamespaceRef"]

    listed = _namespace_ids_by_name(sd, ns_name)
    assert listed == [namespace_id], (
        f"ListNamespaces for {ns_name!r} reports {listed!r}, expected only the stack's Ref {namespace_id!r}"
    )

    namespace = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert namespace["Type"] == "DNS_PRIVATE", (
        f"GetNamespace Type {namespace['Type']!r}, expected DNS_PRIVATE"
    )
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
    assert found["Attributes"].get("AWS_INSTANCE_IPV4") == "192.0.2.77", (
        f"expected AWS_INSTANCE_IPV4=192.0.2.77 for instance {instance_id!r} via DiscoverInstances, "
        f"got {found['Attributes']!r}"
    )

    _delete_stack(cfn, stack_id)

    _NAMESPACE_GONE = ("NamespaceNotFound", "")
    expect_error(lambda: sd.get_namespace(Id=namespace_id), *_NAMESPACE_GONE)

    listed_after = _namespace_ids_by_name(sd, ns_name)
    assert listed_after == [], (
        f"ListNamespaces still lists {ns_name!r} after DeleteStack: {listed_after!r}"
    )

    _ZONE_GONE = ("NoSuchHostedZone", f"No hosted zone found with ID: {zone_id}")
    expect_error(lambda: r53.get_hosted_zone(Id=zone_id), *_ZONE_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
