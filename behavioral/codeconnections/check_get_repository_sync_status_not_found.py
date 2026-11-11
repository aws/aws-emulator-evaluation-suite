"""get-repository-sync-status-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-repository-sync-status-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRepositorySyncStatus against a nonexistent RepositoryLinkId/Branch is rejected."""
    cc = ctx.client("codeconnections")
    fake_id = str(uuid.uuid4())

    code, message = _error_code(
        lambda: cc.get_repository_sync_status(
            Branch="main", RepositoryLinkId=fake_id, SyncType="CFN_STACK_SYNC"
        )
    )
    assert code == "InvalidInputException", "actual_code=" + str(code)
    expected = f"Repository Link with id {fake_id} was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
