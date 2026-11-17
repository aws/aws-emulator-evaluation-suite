"""list-connections-paginates-with-limit-and-next-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connections-paginates-with-limit-and-next-token"
GROUP = "connection"
SERVICES = ["events"]

_CONNECTIONS = 3
_MAX_PAGES = 10


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections with Limit=1 over three connections returns one connection per page and
    together each connection exactly once; Limit above the maximum of 100 and an unissued
    NextToken are both refused.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListConnections.html
    """
    events = ctx.client("events")
    prefix = ctx.unique_name("sim2real-behav-conn-")
    names = {f"{prefix}-{i}" for i in range(_CONNECTIONS)}
    for name in sorted(names):
        events.create_connection(
            Name=name,
            AuthorizationType="API_KEY",
            AuthParameters={
                "ApiKeyAuthParameters": {"ApiKeyName": "sim2real-key", "ApiKeyValue": "sim2real-value"},
            },
        )
        ctx.on_cleanup(lambda n=name: events.delete_connection(Name=n))

    pages: list[list[str]] = []
    token = None
    while True:
        kwargs = {"NamePrefix": prefix, "Limit": 1}
        if token:
            kwargs["NextToken"] = token
        resp = events.list_connections(**kwargs)
        page = [c["Name"] for c in resp.get("Connections", [])]
        assert len(page) <= 1, f"Limit=1 returned a page of {len(page)} connections: {page!r}"
        pages.append(page)
        token = resp.get("NextToken")
        if not token:
            break
        assert len(pages) < _MAX_PAGES, (
            f"ListConnections kept returning a NextToken after {len(pages)} pages for "
            f"{_CONNECTIONS} connections: {pages!r} -- the token does not advance"
        )

    listed = [n for page in pages for n in page]
    assert sorted(listed) == sorted(names), (
        f"the pages together must return each of the {_CONNECTIONS} connections exactly once; "
        f"got {listed!r}"
    )
    assert sum(1 for page in pages if page) == _CONNECTIONS, (
        f"with Limit=1 the {_CONNECTIONS} connections must arrive on {_CONNECTIONS} separate "
        f"pages, got {pages!r}"
    )

    code, message = _error(lambda: events.list_connections(NamePrefix=prefix, Limit=101))
    assert (code, message) == (
        "ValidationException",
        "1 validation error detected: Value '101' at 'limit' failed to satisfy constraint: "
        "Member must have value less than or equal to 100",
    ), f"Limit=101 must be refused, got {code!r} {message!r}"

    code, message = _error(
        lambda: events.list_connections(NamePrefix=prefix, NextToken="c2ltMnJlYWw=")
    )
    assert (code, message) == (
        "ValidationException", "Parameter NextToken is not valid. Reason: The request is malformed.",
    ), f"a NextToken the service never issued must be refused, got {code!r} {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
