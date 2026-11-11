"""connection-delete-removes-and-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-delete-removes-and-not-found"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnection permanently removes the connection: it disappears from
    GetConnection (ResourceNotFoundException) and from ListConnections, and a
    subsequent mutation against the dead ARN is rejected the same way."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]

    # sanity: it exists before delete
    status = cc.get_connection(ConnectionArn=arn)["Connection"]["ConnectionStatus"]
    assert status == "PENDING", f"expected freshly created connection status PENDING, got {status!r}"

    cc.delete_connection(ConnectionArn=arn)

    get_code, get_message = _error(lambda: cc.get_connection(ConnectionArn=arn))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetConnection on a deleted arn to raise ResourceNotFoundException, got {get_code!r}"
    )
    expected = "No connection exists with the ARN"
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    tag_code, tag_message = _error(lambda: cc.tag_resource(ResourceArn=arn, Tags=[{"Key": "sim2real-probe", "Value": "x"}]))
    assert tag_code == "ResourceNotFoundException", (
        f"expected TagResource on a deleted arn to raise ResourceNotFoundException, got {tag_code!r}"
    )
    assert tag_message == expected, f"expected message {expected!r}, got {tag_message!r}"

    arns_after = {c["ConnectionArn"] for c in _iter_connections(cc)}
    assert arn not in arns_after, f"deleted connection {arn} still present in ListConnections"


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _iter_connections(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_connections(**kwargs)
        yield from resp.get("Connections", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
