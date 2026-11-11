"""create-time-tags-list-exactly-across-resource-types."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-time-tags-list-exactly-across-resource-types"
GROUP = "state-machine"
SERVICES = ["ssm"]

_CREATE_TAGS = [{"Key": "owner", "Value": "alpha"}, {"Key": "tier", "Value": "gold"}]


def _sorted_tags(tag_list):
    return sorted(tag_list, key=lambda t: t["Key"])


def _document_content():
    return json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "tag round-trip document",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "run",
                    "inputs": {"runCommand": ["echo hello"]},
                }
            ],
        }
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create-time tags on four SSM resource types list exactly through ListTagsForResource.

    Parameter, Document, MaintenanceWindow and PatchBaseline: AddTagsToResource overwrites and adds
    keys and RemoveTagsFromResource drops only the named key, each read back as the exact TagList.
    """
    ssm = ctx.client("ssm")

    param_name = "/" + ctx.unique_name("sim2real-behav-tagparam-")
    ssm.put_parameter(Name=param_name, Value="v1", Type="String", Tags=_CREATE_TAGS)
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    doc_name = ctx.unique_name("sim2real-behav-tagdoc-")
    ssm.create_document(
        Name=doc_name,
        Content=_document_content(),
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=_CREATE_TAGS,
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-behav-tagmw-"),
        Schedule="rate(7 days)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=False,
        Tags=_CREATE_TAGS,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    baseline_id = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-behav-tagpb-"),
        OperatingSystem="WINDOWS",
        ApprovedPatches=["KB2032276"],
        Tags=_CREATE_TAGS,
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))

    deadline = time.monotonic() + min(60.0, ctx.time_left())
    while True:
        status = ssm.describe_document(Name=doc_name)["Document"]["Status"]
        if status != "Creating" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert status == "Active", f"document status is {status!r}, expected 'Active'"

    resources = [
        ("Parameter", param_name),
        ("Document", doc_name),
        ("MaintenanceWindow", window_id),
        ("PatchBaseline", baseline_id),
    ]
    for resource_type, resource_id in resources:

        def listed(resource_type=resource_type, resource_id=resource_id):
            return _sorted_tags(
                ssm.list_tags_for_resource(ResourceType=resource_type, ResourceId=resource_id)[
                    "TagList"
                ]
            )

        assert listed() == _CREATE_TAGS, (
            f"{resource_type} create-time tags listed as {listed()!r}, expected {_CREATE_TAGS!r}"
        )

        ssm.add_tags_to_resource(
            ResourceType=resource_type,
            ResourceId=resource_id,
            Tags=[{"Key": "tier", "Value": "platinum"}, {"Key": "extra", "Value": "x"}],
        )
        expected = [
            {"Key": "extra", "Value": "x"},
            {"Key": "owner", "Value": "alpha"},
            {"Key": "tier", "Value": "platinum"},
        ]
        after_add = listed()
        assert after_add == expected, (
            f"{resource_type} tags after AddTagsToResource are {after_add!r}, expected {expected!r}"
        )

        ssm.remove_tags_from_resource(
            ResourceType=resource_type, ResourceId=resource_id, TagKeys=["owner"]
        )
        expected = [{"Key": "extra", "Value": "x"}, {"Key": "tier", "Value": "platinum"}]
        after_remove = listed()
        assert after_remove == expected, (
            f"{resource_type} tags after RemoveTagsFromResource are {after_remove!r}, "
            f"expected {expected!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
