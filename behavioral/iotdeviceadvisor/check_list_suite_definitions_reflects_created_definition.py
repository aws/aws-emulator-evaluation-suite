"""list-suite-definitions-reflects-created-definition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-suite-definitions-reflects-created-definition"
GROUP = "lifecycle"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSuiteDefinitions includes a newly created suite and stops including it after delete."""
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
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            da.delete_suite_definition(suiteDefinitionId=suite_id)

    ctx.on_cleanup(_cleanup)

    ids_after_create = _list_all_suite_ids(da)
    assert suite_id in ids_after_create, (
        f"expected {suite_id} in ListSuiteDefinitions after create, got {ids_after_create}"
    )

    da.delete_suite_definition(suiteDefinitionId=suite_id)
    state["deleted"] = True

    ids_after_delete = _list_all_suite_ids(da)
    assert suite_id not in ids_after_delete, (
        f"expected {suite_id} absent from ListSuiteDefinitions after delete, still present in {ids_after_delete}"
    )


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


def _list_all_suite_ids(da, max_pages: int = 25) -> set[str]:
    ids: set[str] = set()
    token = None
    for _ in range(max_pages):
        kwargs = {"maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        resp = da.list_suite_definitions(**kwargs)
        ids.update(i["suiteDefinitionId"] for i in resp.get("suiteDefinitionInformationList", []))
        token = resp.get("nextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
