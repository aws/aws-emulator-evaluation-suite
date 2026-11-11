"""delete-repository-link-removes-it."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-link-removes-it"
GROUP = "repository-link"
SERVICES = ["codestar-connections"]


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    """DeleteRepositoryLink removes the link; GetRepositoryLink then 404s, a repeat
    delete is idempotent-success (real AWS does not reject it), and a genuine
    mutation (UpdateRepositoryLink) on the dead id is rejected.
    """
    csc = ctx.client("codestar-connections")
    conn_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"), ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn_arn))

    link_id = csc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId="sim2real-owner",
        RepositoryName=ctx.unique_name("sim2real-behav-repo-"),
    )["RepositoryLinkInfo"]["RepositoryLinkId"]

    # sanity: it exists before deletion
    link = csc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert link["RepositoryLinkId"] == link_id, link

    csc.delete_repository_link(RepositoryLinkId=link_id)

    code, message = _error_code(lambda: csc.get_repository_link(RepositoryLinkId=link_id))
    assert code == "ResourceNotFoundException", code
    expected_message = f"Repository not found for accountId: {ctx.account} and uuid: {link_id}" + _suffix(404, "ResourceNotFoundException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # DeleteRepositoryLink is idempotent: a repeat delete on the dead id succeeds,
    # it does not 404.
    csc.delete_repository_link(RepositoryLinkId=link_id)

    # a genuine mutation on the now-dead id is rejected, unlike the idempotent delete
    code2, code2_message = _error_code(
        lambda: csc.update_repository_link(ConnectionArn=conn_arn, RepositoryLinkId=link_id)
    )
    assert code2 == "ResourceNotFoundException", code2
    expected_code2_message = f"Repository not found for accountId: {ctx.account} and uuid: {link_id}" + _suffix(404, "ResourceNotFoundException")
    assert code2_message == expected_code2_message, (
        f"the refusal said {code2_message!r}, expected {expected_code2_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
