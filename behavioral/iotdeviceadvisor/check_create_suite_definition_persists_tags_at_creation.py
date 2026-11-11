"""create-suite-definition-persists-tags-at-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-suite-definition-persists-tags-at-creation"
GROUP = "tagging"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed to CreateSuiteDefinition are retrievable via ListTagsForResource."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-suite-")

    create_resp = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )
    suite_id = create_resp["suiteDefinitionId"]
    suite_arn = create_resp["suiteDefinitionArn"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))

    tags = da.list_tags_for_resource(resourceArn=suite_arn)["tags"]
    assert tags == {"env": "sim2real", "purpose": "behavioral-check"}, (
        f"ListTagsForResource expected {{'env': 'sim2real', 'purpose': 'behavioral-check'}}, got {tags}"
    )

    # GetSuiteDefinition also surfaces the same tags
    got_tags = da.get_suite_definition(suiteDefinitionId=suite_id).get("tags")
    assert got_tags == {"env": "sim2real", "purpose": "behavioral-check"}, (
        f"GetSuiteDefinition expected {{'env': 'sim2real', 'purpose': 'behavioral-check'}}, got {got_tags}"
    )


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
