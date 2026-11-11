"""deploy-iot-softwarepackage-version-and-fleetmetric-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iot-softwarepackage-version-and-fleetmetric-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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

_SHADOW_FILTER = {"namedShadowNames": ["$package"]}


def _index_active(iot, index_name, timeout_s=180.0):
    """Poll DescribeIndex every 3 s for ``index_name`` to report ACTIVE; any other status
    (BUILDING, REBUILDING while a new configuration applies) keeps polling."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = iot.describe_index(indexName=index_name)["indexStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"index {index_name} still {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _template(package_name, version_name, description, thing_name, metric_name,
              with_version=True):
    resources = {
        "Package": {
            "Type": "AWS::IoT::SoftwarePackage",
            "Properties": {"PackageName": package_name, "Description": description},
        },
        "Thing": {
            "Type": "AWS::IoT::Thing",
            "Properties": {"ThingName": thing_name},
        },
        "FleetMetric": {
            "Type": "AWS::IoT::FleetMetric",
            "Properties": {
                "MetricName": metric_name,
                "QueryString": f"thingName:{thing_name}",
                "AggregationType": {"Name": "Statistics", "Values": ["count"]},
                "Period": 300,
                "AggregationField": "registry.version",
                "IndexName": "AWS_Things",
            },
            "DependsOn": "Thing",
        },
    }
    outputs = {
        "PackageRef": {"Value": {"Ref": "Package"}},
        "PackageArn": {"Value": {"Fn::GetAtt": ["Package", "PackageArn"]}},
        "ThingRef": {"Value": {"Ref": "Thing"}},
        "MetricRef": {"Value": {"Ref": "FleetMetric"}},
        "MetricArn": {"Value": {"Fn::GetAtt": ["FleetMetric", "MetricArn"]}},
    }
    if with_version:
        resources["Version"] = {
            "Type": "AWS::IoT::SoftwarePackageVersion",
            "Properties": {
                "PackageName": {"Ref": "Package"},
                "VersionName": version_name,
                "Description": description,
            },
            "DependsOn": "Package",
        }
        outputs.update({
            "VersionRef": {"Value": {"Ref": "Version"}},
            "VersionArn": {"Value": {"Fn::GetAtt": ["Version", "PackageVersionArn"]}},
            "VersionStatus": {"Value": {"Fn::GetAtt": ["Version", "Status"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """A CloudFormation IoT package, version, thing and fleet metric read back through IoT.

    Ref, GetAtt and every templated property match IoT; an update dropping the version removes
    it while its package answers, and the stack delete removes the rest.
    """
    cf = ctx.client("cloudformation")
    iot = ctx.client("iot")

    prior = iot.get_indexing_configuration()["thingIndexingConfiguration"]
    prior_input = {k: v for k, v in prior.items() if k != "managedFields"}
    assert prior["thingIndexingMode"] == "OFF", (
        f"iot-indexing singleton already in use: {prior!r}"
    )
    ctx.on_cleanup(lambda: iot.update_indexing_configuration(thingIndexingConfiguration=prior_input))
    iot.update_indexing_configuration(thingIndexingConfiguration={
        "thingIndexingMode": "REGISTRY_AND_SHADOW",
        "namedShadowIndexingMode": "ON",
        "filter": _SHADOW_FILTER,
    })
    _index_active(iot, "AWS_Things")

    stack = ctx.unique_name("sim2real-cfniotpkg-")
    package = ctx.unique_name("sim2real-cfniotpkg-p-")
    thing = ctx.unique_name("sim2real-cfniotpkg-t-")
    metric = ctx.unique_name("sim2real-cfniotpkg-m-")
    version = "v1"
    description = "sim2real software package round trip"

    stack_id = create_stack(ctx, cf, stack,
                            _template(package, version, description, thing, metric))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    package_arn = f"arn:{partition}:iot:{ctx.region}:{ctx.account}:package/{package}"
    version_arn = f"arn:{partition}:iot:{ctx.region}:{ctx.account}:package/{package}/version/{version}"
    metric_arn = f"arn:{partition}:iot:{ctx.region}:{ctx.account}:fleetmetric/{metric}"

    assert out["PackageRef"] == package, f"Ref {out['PackageRef']!r} != {package!r}"
    assert out["PackageArn"] == package_arn, f"GetAtt PackageArn {out['PackageArn']!r}"
    assert out["VersionRef"] == f"{package}|{version}", (
        f"Ref {out['VersionRef']!r} != {package}|{version}"
    )
    assert out["VersionArn"] == version_arn, f"GetAtt PackageVersionArn {out['VersionArn']!r}"
    assert out["VersionStatus"] == "DRAFT", f"GetAtt Status {out['VersionStatus']!r} != DRAFT"
    assert out["ThingRef"] == thing, f"Ref {out['ThingRef']!r} != {thing!r}"
    assert out["MetricRef"] == metric, f"Ref {out['MetricRef']!r} != {metric!r}"
    assert out["MetricArn"] == metric_arn, f"GetAtt MetricArn {out['MetricArn']!r}"

    # Independent reads: List* by name, never a read keyed by the Ref.
    listed_pkg = [p["packageName"] for p in paginate(iot, "list_packages", "packageSummaries")
                 if p["packageName"] == package]
    assert listed_pkg == [package], f"ListPackages found {listed_pkg!r} for {package!r}"
    listed_metrics = [m["metricName"] for m in paginate(iot, "list_fleet_metrics", "fleetMetrics")
                      if m["metricName"] == metric]
    assert listed_metrics == [metric], f"ListFleetMetrics found {listed_metrics!r} for {metric!r}"

    got_pkg = iot.get_package(packageName=package)
    assert got_pkg["packageArn"] == package_arn, f"GetPackage arn {got_pkg['packageArn']!r}"
    assert got_pkg["description"] == description, (
        f"GetPackage description {got_pkg['description']!r}"
    )

    got_ver = iot.get_package_version(packageName=package, versionName=version)
    assert got_ver["packageVersionArn"] == version_arn, (
        f"GetPackageVersion arn {got_ver['packageVersionArn']!r}"
    )
    assert got_ver["description"] == description, (
        f"GetPackageVersion description {got_ver['description']!r}"
    )
    assert got_ver["status"] == "DRAFT", f"GetPackageVersion status {got_ver['status']!r}"

    got_thing = iot.describe_thing(thingName=thing)
    assert got_thing["thingName"] == thing, f"DescribeThing name {got_thing['thingName']!r}"

    got_metric = iot.describe_fleet_metric(metricName=metric)
    assert got_metric["metricArn"] == metric_arn, f"DescribeFleetMetric arn {got_metric['metricArn']!r}"
    assert got_metric["queryString"] == f"thingName:{thing}", (
        f"DescribeFleetMetric queryString {got_metric['queryString']!r}"
    )
    assert got_metric["aggregationType"] == {"name": "Statistics", "values": ["count"]}, (
        f"DescribeFleetMetric aggregationType {got_metric['aggregationType']!r}"
    )
    assert got_metric["period"] == 300, f"DescribeFleetMetric period {got_metric['period']!r}"
    assert got_metric["aggregationField"] == "registry.version", (
        f"DescribeFleetMetric aggregationField {got_metric['aggregationField']!r}"
    )
    assert got_metric["indexName"] == "AWS_Things", (
        f"DescribeFleetMetric indexName {got_metric['indexName']!r}"
    )

    # Child before parent: the update drops only the version while its package answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(
        package, version, description, thing, metric, with_version=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"version-removing update ended {status!r}"
    kept = iot.get_package(packageName=package)["packageArn"]
    assert kept == package_arn, f"after dropping the version the package reads {kept!r}"
    version_gone = ("ResourceNotFoundException",
                    f"PackageVersion {version} for package {package} not found")
    expect_error(lambda: iot.get_package_version(packageName=package, versionName=version),
                 *version_gone)

    delete_stack(cf, stack_id)
    package_gone = ("ResourceNotFoundException", f"Package {package} not found")
    expect_error(lambda: iot.get_package(packageName=package), *package_gone)
    thing_gone = ("ResourceNotFoundException", f"Thing {ctx.account}:{thing} not found.")
    expect_error(lambda: iot.describe_thing(thingName=thing), *thing_gone)
    # IoT returns the SDK-style "An error occurred ..." preamble inside this Error.Message itself.
    metric_gone = ("ResourceNotFoundException",
                   "An error occurred (ResourceNotFoundException) when calling the "
                   f"DescribeFleetMetric operation: FleetMetric {ctx.account}:{metric} not found.")
    expect_error(lambda: iot.describe_fleet_metric(metricName=metric), *metric_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
