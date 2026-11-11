"""get-suite-definition-nonexistent-id-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-suite-definition-nonexistent-id-not-found"
GROUP = "overly-permissive"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSuiteDefinition on a well-formed but non-existent id is rejected as NotFound;
    a real suite id is still readable normally."""
    da = ctx.client("iotdeviceadvisor")
    fake_id = str(uuid.uuid4())

    code, message = _error(lambda: da.get_suite_definition(suiteDefinitionId=fake_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent "
        f"suiteDefinitionId, got {code!r}"
    )
    expected_message = f"Unable to find resource with suiteDefinitionId: {fake_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect check: the non-existent id never shows up in a listing
    all_ids = _list_all_suite_ids(da)
    assert fake_id not in all_ids, f"nonexistent suite {fake_id} unexpectedly listed in {all_ids!r}"

    # positive control: a real suite id is readable
    role_arn = _dummy_role_arn(ctx)
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

    got = da.get_suite_definition(suiteDefinitionId=suite_id)
    assert got["suiteDefinitionId"] == suite_id, (
        f"positive control: expected GetSuiteDefinition to return the real suite "
        f"{suite_id!r}, got {got.get('suiteDefinitionId')!r}"
    )


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
