"""create-suite-definition-missing-root-group-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-suite-definition-missing-root-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A non-qualification suite with an empty rootGroup is rejected; a valid one still succeeds."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-suite-")

    def _attempt():
        # rootGroup="" is structurally valid (botocore's shape allows a
        # min-length-0 string), so this reaches the service. The service's
        # own rule -- documented on CreateSuiteDefinitionRequest.rootGroup --
        # is that an empty rootGroup is only permitted when
        # intendedForQualification is true; here it is false, so the
        # rejection is the server's, not the SDK's.
        da.create_suite_definition(
            suiteDefinitionConfiguration={
                "suiteDefinitionName": name,
                "rootGroup": "",
                "devicePermissionRoleArn": role_arn,
                "intendedForQualification": False,
            }
        )

    code, message = _error(_attempt)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "Invalid Request: rootGroup cannot be empty for non-qualification test suite"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected attempt did not create any suite with this name
    names_after_rejection = _list_all_suite_names(da)
    assert name not in names_after_rejection, (
        f"expected {name!r} absent after rejected create, but it is listed: {names_after_rejection!r}"
    )

    # positive control: the identical configuration succeeds once rootGroup is supplied
    ok = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        }
    )
    suite_id = ok["suiteDefinitionId"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))
    names_after_success = _list_all_suite_names(da)
    assert name in names_after_success, (
        f"expected {name!r} listed after successful create, but got: {names_after_success!r}"
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


def _list_all_suite_names(da, max_pages: int = 25) -> set[str]:
    names: set[str] = set()
    token = None
    for _ in range(max_pages):
        kwargs = {"maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        resp = da.list_suite_definitions(**kwargs)
        names.update(i["suiteDefinitionName"] for i in resp.get("suiteDefinitionInformationList", []))
        token = resp.get("nextToken")
        if not token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
