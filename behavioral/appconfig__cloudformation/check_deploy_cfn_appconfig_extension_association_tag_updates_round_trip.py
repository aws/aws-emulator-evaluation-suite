"""deploy-cfn-appconfig-extension-association-tag-updates-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-extension-association-tag-updates-round-trip"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _poll_stack(cf, stack_id: str, terminal=_STACK_TERMINAL, deadline_s: float = 300.0) -> str:
    """Poll DescribeStacks until its status lands in ``terminal``; return that status."""
    deadline = time.monotonic() + deadline_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id!r} still {status!r} after {deadline_s:.0f}s")
        time.sleep(3)


def _outputs(cf, stack_id: str) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _template(app_name: str, ext_name: str, tag_map: dict) -> str:
    """One Application, an Extension with a single ON_DEPLOYMENT_START action, and an
    ExtensionAssociation binding the Extension to the Application; all three carry
    ``tag_map`` as their AppConfig Tags property."""
    tag_list = [{"Key": k, "Value": v} for k, v in tag_map.items()]
    resources = {
        "App": {
            "Type": "AWS::AppConfig::Application",
            "Properties": {"Name": app_name, "Tags": tag_list},
        },
        "Ext": {
            "Type": "AWS::AppConfig::Extension",
            "Properties": {
                "Name": ext_name,
                "Actions": {
                    "ON_DEPLOYMENT_START": [{
                        "Name": "notify-default-bus",
                        "Uri": {"Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:"
                                            "${AWS::AccountId}:event-bus/default"},
                    }],
                },
                "Tags": tag_list,
            },
        },
        "ExtAssoc": {
            "Type": "AWS::AppConfig::ExtensionAssociation",
            "Properties": {
                "ExtensionIdentifier": {"Ref": "Ext"},
                "ResourceIdentifier": {"Fn::Sub": "arn:${AWS::Partition}:appconfig:${AWS::Region}:"
                                                  "${AWS::AccountId}:application/${App}"},
                "Tags": tag_list,
            },
        },
    }
    outputs = {
        "AppId": {"Value": {"Ref": "App"}},
        "ExtId": {"Value": {"Ref": "Ext"}},
        "ExtArn": {"Value": {"Fn::GetAtt": ["Ext", "Arn"]}},
        "AssocId": {"Value": {"Ref": "ExtAssoc"}},
        "AssocArn": {"Value": {"Fn::GetAtt": ["ExtAssoc", "Arn"]}},
        "AssocExtensionArn": {"Value": {"Fn::GetAtt": ["ExtAssoc", "ExtensionArn"]}},
        "AssocResourceArn": {"Value": {"Fn::GetAtt": ["ExtAssoc", "ResourceArn"]}},
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _customer_tags(appconfig, arn: str) -> dict:
    """``ListTagsForResource`` on ``arn`` with CloudFormation's own ``aws:`` tags dropped."""
    got = appconfig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {k: v for k, v in got.items() if not k.startswith("aws:")}


def _assert_identity(appconfig, out: dict, expect_version: int | None, where: str) -> int:
    """GetExtension and GetExtensionAssociation agree with the stack's own outputs; returns the
    extension's VersionNumber, which the caller compares across calls."""
    ext = appconfig.get_extension(ExtensionIdentifier=out["ExtId"])
    assert ext["Id"] == out["ExtId"], f"{where}: GetExtension Id {ext['Id']!r} != {out['ExtId']!r}"
    assert ext["Arn"] == out["ExtArn"], f"{where}: GetExtension Arn {ext['Arn']!r} != {out['ExtArn']!r}"
    if expect_version is not None:
        assert ext["VersionNumber"] == expect_version, (
            f"{where}: extension VersionNumber {ext['VersionNumber']!r} != {expect_version!r}"
        )

    assoc = appconfig.get_extension_association(ExtensionAssociationId=out["AssocId"])
    assert assoc["Id"] == out["AssocId"], f"{where}: GetExtensionAssociation Id {assoc['Id']!r} != {out['AssocId']!r}"
    assert assoc["ExtensionArn"] == out["AssocExtensionArn"], (
        f"{where}: association ExtensionArn {assoc['ExtensionArn']!r} != {out['AssocExtensionArn']!r}"
    )
    assert assoc["ResourceArn"] == out["AssocResourceArn"], (
        f"{where}: association ResourceArn {assoc['ResourceArn']!r} != {out['AssocResourceArn']!r}"
    )
    return ext["VersionNumber"]


def _assert_tags(appconfig, out: dict, expected: dict, where: str) -> None:
    for label, arn in (("extension", out["ExtArn"]), ("extension association", out["AssocArn"])):
        got = _customer_tags(appconfig, arn)
        assert got == expected, f"{where}: {label} tags {got!r}, expected {expected!r}"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack holding an AppConfig Extension and an ExtensionAssociation to an Application
    reaches UPDATE_COMPLETE on a Tags-only change and on clearing Tags, every output and
    GetExtension/GetExtensionAssociation identity unchanged, ListTagsForResource tracking Tags."""
    cf = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    stack = ctx.unique_name("sim2real-acfgext-stack-")
    app_name = ctx.unique_name("sim2real-acfgext-app-")
    ext_name = ctx.unique_name("sim2real-acfgext-ext-")

    tags_v1 = {"environment": "staging"}
    tags_v2 = {"environment": "production", "team": "platform"}
    tags_v3: dict = {}

    stack_id = cf.create_stack(
        StackName=stack, TemplateBody=_template(app_name, ext_name, tags_v1),
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy(cf, stack_id))

    status = _poll_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    out1 = _outputs(cf, stack_id)
    version = _assert_identity(appconfig, out1, None, "after create")
    _assert_tags(appconfig, out1, tags_v1, "after create")

    cf.update_stack(StackName=stack_id, TemplateBody=_template(app_name, ext_name, tags_v2))
    status = _poll_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"tag-value-change update ended {status!r}"

    out2 = _outputs(cf, stack_id)
    assert out2 == out1, f"a Tags-only update changed an output: {out2!r} vs {out1!r}"
    _assert_identity(appconfig, out2, version, "after changing a value and adding a key")
    _assert_tags(appconfig, out2, tags_v2, "after changing a value and adding a key")

    cf.update_stack(StackName=stack_id, TemplateBody=_template(app_name, ext_name, tags_v3))
    status = _poll_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"tag-removing update ended {status!r}"

    out3 = _outputs(cf, stack_id)
    assert out3 == out1, f"the tag-removing update changed an output: {out3!r} vs {out1!r}"
    _assert_identity(appconfig, out3, version, "after removing Tags")
    _assert_tags(appconfig, out3, tags_v3, "after removing Tags")


def _destroy(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
