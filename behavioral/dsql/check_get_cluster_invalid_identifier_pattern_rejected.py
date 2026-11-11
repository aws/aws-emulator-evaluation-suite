"""get-cluster-invalid-identifier-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-cluster-invalid-identifier-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCluster rejects an identifier that fails the ^[a-z0-9]{26}$ pattern (uppercase
    characters, wrong length) with ValidationException -- distinct from the not-found case --
    while a well-formed identifier for a real cluster is accepted."""
    dsql = ctx.client("dsql")

    malformed_code, malformed_message = _error(lambda: dsql.get_cluster(identifier="TOO-SHORT-AND-UPPERCASE"))
    assert malformed_code == "ValidationException", malformed_code
    assert malformed_message == (
        "1 validation error detected: Value at 'identifier' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-z0-9]{26}"
    ), malformed_message

    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "get-cluster-invalid-identifier-pattern-rejected"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))
    ok = dsql.get_cluster(identifier=identifier)
    assert ok["identifier"] == identifier, f"expected {identifier}, got {ok.get('identifier')!r}"


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
