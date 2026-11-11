"""create-repository-link-duplicate-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-repository-link-duplicate-rejected"
GROUP = "overly-permissive"
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
    raise AssertionError(f"expected rejection, but call succeeded: {result!r}")


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


def _count_links_for(cc, connection_arn: str, owner_id: str, repository_name: str) -> int:
    count = 0
    token = None
    for _ in range(20):  # bounded pagination, generous for a test account
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_repository_links(**kwargs)
        for link in page.get("RepositoryLinks", []):
            if (
                link.get("ConnectionArn") == connection_arn
                and link.get("OwnerId") == owner_id
                and link.get("RepositoryName") == repository_name
            ):
                count += 1
        token = page.get("NextToken")
        if not token:
            break
    return count


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateRepositoryLink for the same connection, owner and repository raises
    ResourceAlreadyExistsException and one link remains, while a link for another repository on the
    same connection is created."""
    cc = ctx.client("codeconnections")
    conn_name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(
        ConnectionName=conn_name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    owner_id = ctx.unique_name("s2rowner")[:64]
    repo_name = ctx.unique_name("s2rrepo")[:64]

    first = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner_id,
        RepositoryName=repo_name,
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["RepositoryLinkInfo"]
    first_link_id = first["RepositoryLinkId"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=first_link_id))

    code, message = _error_code(
        lambda: cc.create_repository_link(
            ConnectionArn=conn_arn, OwnerId=owner_id, RepositoryName=repo_name
        )
    )
    assert code == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException for a duplicate "
        f"(connection, owner, repo) triple, got {code!r}"
    )
    expected_message = f"RepoConfiguration already exists. Arn: arn:aws:codestar-connections:{ctx.region}:{ctx.account}:repository-link/{first_link_id}" + _suffix(409, "ResourceAlreadyExistsException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # effect absent: still exactly one link for this (connection, owner, repo) triple
    dup_count = _count_links_for(cc, conn_arn, owner_id, repo_name)
    assert dup_count == 1, (
        f"expected exactly one link for ({conn_arn}, {owner_id}, {repo_name}) "
        f"after the rejected duplicate, found {dup_count}"
    )

    # positive control: a different repository name on the same connection still succeeds
    other_repo_name = ctx.unique_name("s2rrepo2")[:64]
    second = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner_id,
        RepositoryName=other_repo_name,
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["RepositoryLinkInfo"]
    second_link_id = second["RepositoryLinkId"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=second_link_id))
    assert second_link_id != first_link_id, (
        f"positive-control link reused the duplicate-rejected link id {first_link_id!r}"
    )

    # terminal read: independent of the mutating CreateRepositoryLink call
    got_second = cc.get_repository_link(RepositoryLinkId=second_link_id)["RepositoryLinkInfo"]
    assert got_second.get("RepositoryName") == other_repo_name, (
        f"expected an independent GetRepositoryLink read to show "
        f"RepositoryName={other_repo_name!r}, got {got_second.get('RepositoryName')!r}"
    )
    other_count = _count_links_for(cc, conn_arn, owner_id, other_repo_name)
    assert other_count == 1, (
        f"expected exactly one link for the positive-control repo "
        f"({conn_arn}, {owner_id}, {other_repo_name}), found {other_count}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
