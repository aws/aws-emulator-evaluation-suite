"""update-repository-link-not-found."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags

CHECK = "update-repository-link-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRepositoryLink against a nonexistent RepositoryLinkId is rejected."""
    cc = ctx.client("codeconnections")
    fake_id = str(uuid.uuid4())

    code, message = _error_code(lambda: cc.update_repository_link(RepositoryLinkId=fake_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent RepositoryLinkId, got {code!r}"
    )
    expected_message = f"Repository not found for accountId: {ctx.account} and UUID: {fake_id}" + _suffix(404, "ResourceNotFoundException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # positive control: the API itself is otherwise functional and the bogus id is absent
    resp = cc.list_repository_links()
    assert "RepositoryLinks" in resp, f"expected RepositoryLinks key in response, got {resp!r}"
    assert not any(link["RepositoryLinkId"] == fake_id for link in resp["RepositoryLinks"]), (
        f"bogus id {fake_id!r} unexpectedly present in ListRepositoryLinks"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
