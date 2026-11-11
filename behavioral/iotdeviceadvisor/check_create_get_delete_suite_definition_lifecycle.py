"""create-get-delete-suite-definition-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-get-delete-suite-definition-lifecycle"
GROUP = "lifecycle"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSuiteDefinition -> GetSuiteDefinition -> DeleteSuiteDefinition -> GetSuiteDefinition(404)."""
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
    assert create_resp["suiteDefinitionArn"].endswith(suite_id), (
        f"expected arn to end with {suite_id!r}, got {create_resp['suiteDefinitionArn']!r}"
    )

    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            da.delete_suite_definition(suiteDefinitionId=suite_id)

    ctx.on_cleanup(_cleanup)

    get_resp = da.get_suite_definition(suiteDefinitionId=suite_id)
    assert get_resp["suiteDefinitionId"] == suite_id, (
        f"expected suiteDefinitionId {suite_id!r}, got {get_resp['suiteDefinitionId']!r}"
    )
    assert get_resp["suiteDefinitionConfiguration"]["suiteDefinitionName"] == name, (
        f"expected suiteDefinitionName {name!r}, "
        f"got {get_resp['suiteDefinitionConfiguration']['suiteDefinitionName']!r}"
    )
    assert get_resp["suiteDefinitionConfiguration"]["devicePermissionRoleArn"] == role_arn, (
        f"expected devicePermissionRoleArn {role_arn!r}, "
        f"got {get_resp['suiteDefinitionConfiguration']['devicePermissionRoleArn']!r}"
    )
    assert get_resp["latestVersion"] == get_resp["suiteDefinitionVersion"], (
        f"expected latestVersion to equal suiteDefinitionVersion on a freshly created suite, "
        f"got latestVersion={get_resp['latestVersion']!r} "
        f"suiteDefinitionVersion={get_resp['suiteDefinitionVersion']!r}"
    )

    da.delete_suite_definition(suiteDefinitionId=suite_id)
    state["deleted"] = True

    expected_message = f"Unable to find resource with suiteDefinitionId: {suite_id}"
    code, message = _error(lambda: da.get_suite_definition(suiteDefinitionId=suite_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted suite, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A mutation on the dead id is refused too, not just a read
    update_code, update_message = _error(
        lambda: da.update_suite_definition(
            suiteDefinitionId=suite_id,
            suiteDefinitionConfiguration={
                "suiteDefinitionName": name,
                "rootGroup": "",
                "devicePermissionRoleArn": role_arn,
                "intendedForQualification": True,
            },
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected update on a deleted suite to be refused, got {update_code!r}"
    )
    assert update_message == expected_message, f"expected message {expected_message!r}, got {update_message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
