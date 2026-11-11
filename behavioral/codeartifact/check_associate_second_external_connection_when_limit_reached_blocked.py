"""associate-second-external-connection-when-limit-reached-blocked."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "associate-second-external-connection-when-limit-reached-blocked"
GROUP = "overly-permissive"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a second external connection to a repository that has one fails with
    ValidationException and its exact message and leaves only the original, while a different
    connection associates once the first is removed."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository)
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    ca.associate_external_connection(
        domain=domain, repository=repository, externalConnection="public:npmjs"
    )

    code, message = _error(
        lambda: ca.associate_external_connection(
            domain=domain, repository=repository, externalConnection="public:maven-central"
        )
    )
    assert code == "ValidationException", f"expected=ValidationException got={code!r}"
    expected_message = "ExternalConnections for repositories are currently limited to 1"
    assert message == expected_message, f"expected={expected_message!r} got={message!r}"

    # Effect absent: only the original connection is attached.
    repo = ca.describe_repository(domain=domain, repository=repository)["repository"]
    connection_names = {c["externalConnectionName"] for c in repo.get("externalConnections", [])}
    assert connection_names == {"public:npmjs"}, f"expected={{'public:npmjs'}} got={connection_names!r}"

    # Positive control: after freeing the slot, associating a different connection
    # succeeds -- the earlier rejection was about the limit, not the mechanism.
    ca.disassociate_external_connection(
        domain=domain, repository=repository, externalConnection="public:npmjs"
    )
    ca.associate_external_connection(
        domain=domain, repository=repository, externalConnection="public:maven-central"
    )
    ctx.on_cleanup(
        lambda: ca.disassociate_external_connection(
            domain=domain, repository=repository, externalConnection="public:maven-central"
        )
    )
    repo_after = ca.describe_repository(domain=domain, repository=repository)["repository"]
    connection_names_after = {c["externalConnectionName"] for c in repo_after.get("externalConnections", [])}
    assert connection_names_after == {"public:maven-central"}, (
        f"expected={{'public:maven-central'}} got={connection_names_after!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
