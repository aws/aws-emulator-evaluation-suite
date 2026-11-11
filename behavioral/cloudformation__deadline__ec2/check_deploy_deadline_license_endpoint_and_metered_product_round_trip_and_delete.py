"""deploy-deadline-license-endpoint-and-metered-product-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-deadline-license-endpoint-and-metered-product-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "deadline", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.120.0.0/16"
_SUBNET_CIDR = "10.120.1.0/24"


def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


def _template(az, tag_value, product_id=None):
    """A VPC, subnet and SG, a LicenseEndpoint in them, and optionally a MeteredProduct on it."""
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR, "AvailabilityZone": az,
        }},
        "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "GroupDescription": "sim2real deadline license endpoint",
        }},
        "LicenseEndpoint": {"Type": "AWS::Deadline::LicenseEndpoint", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "SubnetIds": [{"Ref": "Subnet"}],
            "SecurityGroupIds": [{"Ref": "Sg"}],
            "Tags": [{"Key": "sim2real-dl", "Value": tag_value}],
        }},
    }
    outputs = {
        "VpcId": {"Value": {"Ref": "Vpc"}},
        "SubnetId": {"Value": {"Ref": "Subnet"}},
        "SgId": {"Value": {"Ref": "Sg"}},
        "LicenseEndpointRef": {"Value": {"Ref": "LicenseEndpoint"}},
        "LicenseEndpointArn": {"Value": {"Fn::GetAtt": ["LicenseEndpoint", "Arn"]}},
        "LicenseEndpointId": {"Value": {"Fn::GetAtt": ["LicenseEndpoint", "LicenseEndpointId"]}},
        "LicenseEndpointDnsName": {"Value": {"Fn::GetAtt": ["LicenseEndpoint", "DnsName"]}},
        "LicenseEndpointStatus": {"Value": {"Fn::GetAtt": ["LicenseEndpoint", "Status"]}},
    }
    if product_id is not None:
        resources["MeteredProduct"] = {"Type": "AWS::Deadline::MeteredProduct", "Properties": {
            "LicenseEndpointId": {"Fn::GetAtt": ["LicenseEndpoint", "LicenseEndpointId"]},
            "ProductId": product_id,
        }}
        outputs.update({
            "MeteredProductRef": {"Value": {"Ref": "MeteredProduct"}},
            "MeteredProductFamily": {"Value": {"Fn::GetAtt": ["MeteredProduct", "Family"]}},
            "MeteredProductVendor": {"Value": {"Fn::GetAtt": ["MeteredProduct", "Vendor"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _usable_az(ec2, region):
    """An AZ both available in this region and offered by the Deadline license-endpoint service."""
    services = ec2.describe_vpc_endpoint_services(
        ServiceNames=[f"com.amazonaws.{region}.deadline.management"]
    )["ServiceDetails"]
    assert services, "no Deadline Cloud license-endpoint VPC endpoint service in this region"
    offered = set(services[0]["AvailabilityZones"])
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers the license-endpoint service; offered {sorted(offered)!r}"
    return usable[0]


def _available_product(dl):
    products = paginate(dl, "list_available_metered_products", "meteredProducts")
    assert products, "ListAvailableMeteredProducts returned no products"
    return products[0]


def _endpoint(dl, out):
    """The stack's license endpoint, found by an independent ListLicenseEndpoints read by VPC."""
    listed = [e for e in paginate(dl, "list_license_endpoints", "licenseEndpoints")
              if e["vpcId"] == out["VpcId"]]
    assert [e["licenseEndpointId"] for e in listed] == [out["LicenseEndpointId"]], (
        f"ListLicenseEndpoints in {out['VpcId']!r}: {listed!r}"
    )
    le = dl.get_license_endpoint(licenseEndpointId=listed[0]["licenseEndpointId"])
    got = {k: le[k] for k in ("status", "vpcId", "subnetIds", "securityGroupIds")}
    want = {"status": "READY", "vpcId": out["VpcId"], "subnetIds": [out["SubnetId"]],
            "securityGroupIds": [out["SgId"]]}
    assert got == want, f"GetLicenseEndpoint reads {got!r}, expected {want!r}"
    return le


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation LicenseEndpoint and MeteredProduct read back through Deadline.

    Ref and GetAtts match an independent ListLicenseEndpoints read and the tags read back; an update
    dropping the MeteredProduct un-lists it from the still-READY endpoint, which the delete removes.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    dl = ctx.client("deadline")
    az = _usable_az(ec2, ctx.region)
    product = _available_product(dl)
    stack = ctx.unique_name("sim2real-deadline-le-")

    stack_id = create_stack(ctx, cfn, stack, _template(az, stack, product["productId"]))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {_reasons(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    le = _endpoint(dl, out)
    le_id = le["licenseEndpointId"]
    le_arn = f"arn:{partition}:deadline:{ctx.region}:{ctx.account}:license-endpoint/{le_id}"
    got = (out["LicenseEndpointRef"], out["LicenseEndpointArn"], out["LicenseEndpointStatus"],
           out["LicenseEndpointDnsName"])
    assert got == (le_arn, le_arn, le["status"], le["dnsName"]), (
        f"Ref/GetAtt Arn, Status, DnsName {got!r}; Deadline reads {le!r}"
    )
    tags_ = {k: v for k, v in dl.list_tags_for_resource(resourceArn=le_arn)["tags"].items()
             if not k.startswith("aws:")}
    assert tags_ == {"sim2real": stack, "sim2real-dl": stack}, f"endpoint tags {tags_!r}"

    listed = paginate(dl, "list_metered_products", "meteredProducts", licenseEndpointId=le_id)
    assert listed == [product], f"ListMeteredProducts {listed!r}, expected {product!r}"
    mp_arn = f"{le_arn}/metered-product/{product['productId']}"
    # The port is graded by the listing above: the integer Port GetAtt is no stack output.
    got = (out["MeteredProductRef"], out["MeteredProductFamily"], out["MeteredProductVendor"])
    assert got == (mp_arn, product["family"], product["vendor"]), (
        f"MeteredProduct Ref/Family/Vendor {got!r}"
    )

    # The metered product's own delete: an update drops it while the endpoint stays READY.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(az, stack))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"product-removing update ended {status!r}"
    after = paginate(dl, "list_metered_products", "meteredProducts", licenseEndpointId=le_id)
    assert after == [], f"metered products on {le_id!r} after the update: {after!r}"
    assert _endpoint(dl, out)["licenseEndpointId"] == le_id, "the endpoint changed"

    delete_stack(cfn, stack_id)
    refused = (
        "ResourceNotFoundException",
        f"Resource of type license-endpoint with id {le_id} does not exist.",
    )
    expect_error(lambda: dl.get_license_endpoint(licenseEndpointId=le_id), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
