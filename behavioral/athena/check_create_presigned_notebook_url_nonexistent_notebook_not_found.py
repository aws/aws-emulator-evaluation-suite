"""create-presigned-notebook-url-nonexistent-notebook-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-presigned-notebook-url-nonexistent-notebook-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePresignedNotebookUrl for a session id that does not exist fails InvalidRequestException
    rather than returning a URL."""
    athena = ctx.client("athena")
    fake_session_id = str(uuid.uuid4())

    code, message = _error(lambda: athena.create_presigned_notebook_url(SessionId=fake_session_id))
    assert code == "InvalidRequestException", (
        f"CreatePresignedNotebookUrl: expected InvalidRequestException, got {code}"
    )
    # AWS answers an unresolvable session id with its generic authorization refusal.
    assert message == "Not authorized to make this request.", repr(message)


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"CreatePresignedNotebookUrl: real AWS rejects a nonexistent SessionId, but this "
        f"call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
