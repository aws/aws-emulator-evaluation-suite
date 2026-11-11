"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags that are then visible via ListTagsForResource."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-suite-")

    create_resp = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        }
    )
    suite_id = create_resp["suiteDefinitionId"]
    suite_arn = create_resp["suiteDefinitionArn"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))

    before = da.list_tags_for_resource(resourceArn=suite_arn)["tags"]
    assert before == {}, f"expected no tags on a freshly created suite, got {before!r}"

    da.tag_resource(resourceArn=suite_arn, tags={"k1": "v1", "k2": "v2"})

    after = da.list_tags_for_resource(resourceArn=suite_arn)["tags"]
    assert after == {
        "k1": "v1",
        "k2": "v2",
    }, f"expected tags {{'k1': 'v1', 'k2': 'v2'}} after TagResource, got {after!r}"


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
