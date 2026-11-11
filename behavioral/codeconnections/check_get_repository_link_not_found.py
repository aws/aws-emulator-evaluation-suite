"""get-repository-link-not-found."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags

CHECK = "get-repository-link-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


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


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRepositoryLink raises ResourceNotFoundException for a never-valid id and for a deleted link's
    id, while the link reads back before its delete."""
    cc = ctx.client("codeconnections")

    conn_name = ctx.unique_name("sim2real-conn-")[:32]
    conn_arn = cc.create_connection(
        ConnectionName=conn_name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    owner = ctx.unique_name("s2rowner")[:32]
    repo = ctx.unique_name("s2rrepo")[:32]
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: cc.delete_repository_link(RepositoryLinkId=link_id)))

    # positive control: the real link reads back
    info = cc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert info["RepositoryLinkId"] == link_id, (
        f"expected the just-created repository link to read back with id {link_id!r}, "
        f"got {info['RepositoryLinkId']!r}"
    )

    # negative, class 1: an id that was never valid
    fake_id = str(uuid.uuid4())
    fake_code, fake_code_message = _error_code(lambda: cc.get_repository_link(RepositoryLinkId=fake_id))
    assert fake_code == "ResourceNotFoundException", (
        f"expected GetRepositoryLink on a never-created id to fail with "
        f"ResourceNotFoundException, got {fake_code!r}"
    )
    expected_fake_code_message = f"Repository not found for accountId: {ctx.account} and UUID: {fake_id}" + _suffix(404, "ResourceNotFoundException")
    assert fake_code_message == expected_fake_code_message, (
        f"the refusal said {fake_code_message!r}, expected {expected_fake_code_message!r}"
    )

    # negative, class 2: an id that was real and is now deleted -- and gone from the independent
    # list read too
    cc.delete_repository_link(RepositoryLinkId=link_id)
    deleted_code, deleted_code_message = _error_code(lambda: cc.get_repository_link(RepositoryLinkId=link_id))
    assert deleted_code == "ResourceNotFoundException", (
        f"expected GetRepositoryLink on a deleted id to fail with "
        f"ResourceNotFoundException, got {deleted_code!r}"
    )
    expected_deleted_code_message = f"Repository not found for accountId: {ctx.account} and uuid: {link_id}" + _suffix(404, "ResourceNotFoundException")
    assert deleted_code_message == expected_deleted_code_message, (
        f"the refusal said {deleted_code_message!r}, expected {expected_deleted_code_message!r}"
    )
    remaining_ids = {link["RepositoryLinkId"] for link in _iter_repository_links(cc)}
    assert link_id not in remaining_ids, (
        f"expected the deleted repository link {link_id!r} to be absent from "
        f"ListRepositoryLinks, but it was still listed"
    )


def _iter_repository_links(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_repository_links(**kwargs)
        yield from resp.get("RepositoryLinks", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
