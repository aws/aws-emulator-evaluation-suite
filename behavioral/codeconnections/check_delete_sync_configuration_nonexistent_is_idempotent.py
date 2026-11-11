"""delete-sync-configuration-nonexistent-is-idempotent."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "delete-sync-configuration-nonexistent-is-idempotent"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSyncConfiguration on a resource with no sync configuration returns 200 twice, while
    GetSyncConfiguration before and after raises ResourceNotFoundException."""
    cc = ctx.client("codeconnections")
    resource_name = ctx.unique_name("s2rsync")[:100]

    # must not already exist
    code, message = _error_code(
        lambda: cc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException before delete, got {code!r}"
    expected_message = f"CloudFormation Stack Sync configuration not found for accountId: {ctx.account} and configTarget: cfn-stack-sync/arn:aws:cloudformation:{ctx.region}:{ctx.account}:stack/{resource_name}" + _suffix(404, "ResourceNotFoundException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # deleting a sync configuration that never existed does not raise ...
    resp = cc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from delete of a never-existing sync config, got "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # ... and calling it again is identically idempotent, not "succeeds exactly once"
    resp2 = cc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the second delete of the same never-existing sync config to also return 200, got "
        f"{resp2['ResponseMetadata']['HTTPStatusCode']}"
    )

    # independent read at the destination: the "successful" deletes created nothing
    code_after, code_after_message = _error_code(
        lambda: cc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after idempotent deletes, got {code_after!r}"
    )
    expected_code_after_message = f"CloudFormation Stack Sync configuration not found for accountId: {ctx.account} and configTarget: cfn-stack-sync/arn:aws:cloudformation:{ctx.region}:{ctx.account}:stack/{resource_name}" + _suffix(404, "ResourceNotFoundException")
    assert code_after_message == expected_code_after_message, (
        f"the refusal said {code_after_message!r}, expected {expected_code_after_message!r}"
    )


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


_REQUEST_ID = re.compile(r"Request ID: [0-9a-f-]+;")


def _mask_request_id(message: str) -> str:
    """AWS appends a per-request backend Request ID to every CodeConnections refusal; mask it."""
    return _REQUEST_ID.sub("Request ID: <id>;", message)


def _suffix(status: int, code: str) -> str:
    """The service-framework tail of a CodeConnections refusal message."""
    return (
        f" (Service: CodeConnections; Status Code: {status}; Error Code: {code}; "
        "Request ID: <id>; Proxy: null)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
