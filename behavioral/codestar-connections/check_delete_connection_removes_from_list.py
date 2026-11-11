"""delete-connection-removes-from-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-connection-removes-from-list"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


def _list_all_connection_arns(csc) -> list[str]:
    arns: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = csc.list_connections(**kwargs)
        arns.extend(c["ConnectionArn"] for c in resp.get("Connections", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnection removes the connection from ListConnections' result set and its ARN becomes unusable."""
    csc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-behav-conn-")
    tag_set = [{"Key": "sim2real-env", "Value": "test"}]
    arn = csc.create_connection(ConnectionName=name, ProviderType="GitHub", Tags=tag_set)["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(csc, arn))

    before = _list_all_connection_arns(csc)
    assert arn in before, f"expected {arn} in ListConnections after create, got {before}"

    csc.delete_connection(ConnectionArn=arn)

    after = _list_all_connection_arns(csc)
    assert arn not in after, f"expected {arn} absent from ListConnections after delete, still present in {after}"

    err = _error(lambda: csc.get_connection(ConnectionArn=arn))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetConnection on deleted {arn}, got {err}"
    )
    assert err["Message"] == "No connection exists with the ARN", err["Message"]


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_connection(csc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        csc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
