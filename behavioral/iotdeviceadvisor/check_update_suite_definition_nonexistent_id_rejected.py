"""update-suite-definition-nonexistent-id-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-suite-definition-nonexistent-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSuiteDefinition on a suiteDefinitionId that does not exist fails ResourceNotFoundException with the
    exact message, while a real suite definition updates to its new name."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    fake_id = str(uuid.uuid4())

    def _attempt():
        da.update_suite_definition(
            suiteDefinitionId=fake_id,
            suiteDefinitionConfiguration={
                "suiteDefinitionName": "sim2real-behav-nonexistent",
                "rootGroup": "",
                "devicePermissionRoleArn": role_arn,
                "intendedForQualification": True,
            },
        )

    code, message = _error(_attempt)
    assert code == "ResourceNotFoundException", code
    expected = f"Unable to find resource with suiteDefinitionId: {fake_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no suite definition materialized at that id
    code2, message2 = _error(lambda: da.get_suite_definition(suiteDefinitionId=fake_id))
    assert code2 == "ResourceNotFoundException", code2
    expected2 = f"Unable to find resource with suiteDefinitionId: {fake_id}"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # positive control: updating a real suite definition succeeds
    name = ctx.unique_name("sim2real-behav-suite-")
    created = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        }
    )
    suite_id = created["suiteDefinitionId"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))

    updated = da.update_suite_definition(
        suiteDefinitionId=suite_id,
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name + "-v2",
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
    )
    assert updated["suiteDefinitionId"] == suite_id, updated.get("suiteDefinitionId")
    assert updated["suiteDefinitionName"] == name + "-v2", updated.get("suiteDefinitionName")

    # terminal read is independent of the mutating update call
    fetched = da.get_suite_definition(suiteDefinitionId=suite_id)
    fetched_name = fetched["suiteDefinitionConfiguration"]["suiteDefinitionName"]
    assert fetched_name == name + "-v2", fetched_name


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
