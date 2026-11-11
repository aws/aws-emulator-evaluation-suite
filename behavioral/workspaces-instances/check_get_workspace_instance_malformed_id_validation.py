"""get-workspace-instance-malformed-id-validation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-workspace-instance-malformed-id-validation"
GROUP = "error-semantics"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A WorkspaceInstanceId that fails the ^wsinst-[0-9a-zA-Z]{8,63}$ pattern is rejected
    with ValidationException, distinct from the ResourceNotFoundException a well-formed but
    unknown id would get."""
    wsi = ctx.client("workspaces-instances")

    # 32 chars: within the {15,70} length bound so botocore's client-side length check
    # passes and the request reaches the service, but it fails the wsinst- prefix pattern.
    malformed_id = "not-a-valid-workspace-instance-x"
    code, message = _error(lambda: wsi.get_workspace_instance(WorkspaceInstanceId=malformed_id))
    assert code == "ValidationException", (code, message)
    assert message == (
        "1 validation error detected: Value at 'workspaceInstanceId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: wsinst-[0-9a-zA-Z]{8,63}"
    ), message

    # Discriminator: a well-formed but never-created id must reach the service and get
    # ResourceNotFoundException, not ValidationException — otherwise a target that rejects
    # every GetWorkspaceInstance call with a blanket 400 would pass this check too.
    well_formed_unknown_id = "wsinst-00000000notreal"
    code, message = _error(lambda: wsi.get_workspace_instance(WorkspaceInstanceId=well_formed_unknown_id))
    assert code == "ResourceNotFoundException", (code, message)
    assert message == "Workspace instance is not found", message


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
