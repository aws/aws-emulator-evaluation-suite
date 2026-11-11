"""create-repository-link-duplicate-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-repository-link-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateRepositoryLink for the same connection/owner/repository triple is
    rejected and does not produce a second link; a different repository name still succeeds.
    """
    cc = ctx.client("codestar-connections")
    tag = [{"Key": "sim2real", "Value": "create-repository-link-duplicate-rejected"}]

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32], ProviderType="GitHub", Tags=tag
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo, Tags=tag
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link_id))

    code, message = _error_code(
        lambda: cc.create_repository_link(ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo)
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r}"
    expected_message = f"RepoConfiguration already exists. Arn: arn:aws:codestar-connections:{ctx.region}:{ctx.account}:repository-link/{link_id}" + _suffix(409, "ResourceAlreadyExistsException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # effect absent: still exactly one link for this triple
    links = cc.list_repository_links()["RepositoryLinks"]
    matching = [
        link
        for link in links
        if link["ConnectionArn"] == conn_arn and link["OwnerId"] == owner and link["RepositoryName"] == repo
    ]
    assert len(matching) == 1, f"expected exactly one link for the triple, got {len(matching)}"

    # positive control: a different repository name on the same connection/owner succeeds
    other_repo = ctx.unique_name("sim2real-repo2-")
    other_link_id = cc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=other_repo, Tags=tag
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, other_link_id))
    assert other_link_id != link_id, "expected the two repository links to have distinct ids"

    # terminal read: independent of every create call above -- the destination now lists
    # exactly two distinct links under this connection/owner, one per repository name
    links_after = cc.list_repository_links()["RepositoryLinks"]
    by_repo = {
        link["RepositoryName"]: link["RepositoryLinkId"]
        for link in links_after
        if link["ConnectionArn"] == conn_arn and link["OwnerId"] == owner
    }
    expected = {repo: link_id, other_repo: other_link_id}
    assert by_repo == expected, f"expected links {expected}, got {by_repo}"


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
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


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_repository_link(cc, link_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_repository_link(RepositoryLinkId=link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
