"""create-repository-link-inaccessible-connection-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-repository-link-inaccessible-connection-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepositoryLink with a malformed ConnectionArn raises ValidationException and creates nothing,
    while a PENDING connection with an arbitrary owner and repository links (reachability is checked
    at sync, not create)."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    # negative: malformed ConnectionArn is rejected at the input-validation boundary
    owner = ctx.unique_name("s2rowner")[:32]
    repo = ctx.unique_name("s2rrepo")[:32]
    code, message = _error_code(
        lambda: cc.create_repository_link(
            ConnectionArn="not-an-arn", OwnerId=owner, RepositoryName=repo
        )
    )
    assert code == "ValidationException", "expected ValidationException, actual_code=" + str(code)
    expected = (
        "1 validation error detected: Value at 'connectionArn' failed to satisfy constraint: Member "
        r"must satisfy regular expression pattern: arn:aws(-[\w]+)*:(codestar-connections|codeconnections):"
        r"[a-z0-9\-]+:[0-9]{12}:connection\/[\w\-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    links = list(_iter_repository_links(cc))
    assert not any(link.get("OwnerId") == owner for link in links), (
        "malformed-ARN create_repository_link must create nothing, but a link with "
        "OwnerId=" + owner + " is visible in ListRepositoryLinks"
    )

    # positive control: a well-formed ConnectionArn + arbitrary repo succeeds even
    # though the connection is still PENDING and the repo does not exist upstream
    resp = cc.create_repository_link(
        ConnectionArn=arn,
        OwnerId=owner,
        RepositoryName=repo,
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )
    link_id = resp["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=link_id))
    assert resp["RepositoryLinkInfo"]["ConnectionArn"] == arn, (
        "expected ConnectionArn=" + arn + ", got " + str(resp["RepositoryLinkInfo"]["ConnectionArn"])
    )
    assert resp["RepositoryLinkInfo"]["OwnerId"] == owner, (
        "expected OwnerId=" + owner + ", got " + str(resp["RepositoryLinkInfo"]["OwnerId"])
    )
    assert resp["RepositoryLinkInfo"]["RepositoryName"] == repo, (
        "expected RepositoryName=" + repo + ", got " + str(resp["RepositoryLinkInfo"]["RepositoryName"])
    )

    # terminal reads: independent of the CreateRepositoryLink call that produced them
    got_link = cc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert got_link["OwnerId"] == owner, (
        "GetRepositoryLink expected OwnerId=" + owner + ", got " + str(got_link["OwnerId"])
    )
    assert got_link["RepositoryName"] == repo, (
        "GetRepositoryLink expected RepositoryName=" + repo + ", got " + str(got_link["RepositoryName"])
    )

    got = cc.get_connection(ConnectionArn=arn)["Connection"]
    assert got["ConnectionStatus"] == "PENDING", (
        "expected connection to remain PENDING after an unreachable repository link was "
        "created against it, got " + str(got["ConnectionStatus"])
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        "expected create_repository_link to be rejected, but it succeeded: " + repr(result)
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
