"""list-suite-runs-malformed-version-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-suite-runs-malformed-version-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSuiteRuns with a malformed nextToken fails ValidationException with the exact message, while the same
    call without it, also filtered by an unmatched suiteDefinitionVersion, returns an empty run list."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-suite-")

    created = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )
    suite_id = created["suiteDefinitionId"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))

    bogus_token = "sim2real-behav-not-a-real-pagination-token"

    def _attempt():
        da.list_suite_runs(suiteDefinitionId=suite_id, nextToken=bogus_token)

    code, message = _error(_attempt)
    assert code == "ValidationException", f"expected ValidationException for a malformed nextToken, got {code!r}"
    expected_message = "Invalid nextToken"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the suite itself is untouched by the rejected call
    still_there = da.get_suite_definition(suiteDefinitionId=suite_id)
    assert still_there["suiteDefinitionId"] == suite_id, (
        f"expected suite {suite_id} to still exist after the rejected call, "
        f"got {still_there.get('suiteDefinitionId')!r}"
    )

    # positive control: listing without the bogus token succeeds
    ok = da.list_suite_runs(suiteDefinitionId=suite_id)
    assert ok["suiteRunsList"] == [], f"expected no runs for a fresh suite, got {ok['suiteRunsList']!r}"

    # a well-formed but nonexistent suiteDefinitionVersion filter is NOT an error --
    # it is accepted and simply yields no matching runs
    ok2 = da.list_suite_runs(suiteDefinitionId=suite_id, suiteDefinitionVersion="does-not-exist-99")
    assert ok2["suiteRunsList"] == [], (
        f"expected an unmatched suiteDefinitionVersion filter to yield no runs, got {ok2['suiteRunsList']!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
