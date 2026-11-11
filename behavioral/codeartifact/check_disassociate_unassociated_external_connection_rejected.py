"""disassociate-unassociated-external-connection-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-unassociated-external-connection-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]

_EXTERNAL_CONNECTION = "public:npmjs"


def _error(fn):
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateExternalConnection targeting a connection that is not currently associated
    with the repository is rejected with ResourceNotFoundException, leaving the repository's
    external-connection list untouched."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()
    repo = ctx.unique_name("sim2real-ca-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repo)
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    described = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described.get("externalConnections", []) == [], (
        f"expected a fresh repository to have no external connections, got {described.get('externalConnections')}"
    )

    refusal = _error(
        lambda: ca.disassociate_external_connection(
            domain=domain, repository=repo, externalConnection=_EXTERNAL_CONNECTION
        )
    )
    expected = (
        "ResourceNotFoundException",
        f"The external connection '{_EXTERNAL_CONNECTION}' is not associated with repository "
        f"'{repo}'",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: still no external connection on the repository (independent read).
    described_after = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described_after.get("externalConnections", []) == [], (
        f"expected disassociating a never-associated connection to have no effect, "
        f"got {described_after.get('externalConnections')}"
    )

    # Positive control: once actually associated, disassociation succeeds and removes it.
    associated = ca.associate_external_connection(
        domain=domain, repository=repo, externalConnection=_EXTERNAL_CONNECTION
    )["repository"]
    names = {c["externalConnectionName"] for c in associated.get("externalConnections", [])}
    assert _EXTERNAL_CONNECTION in names, f"expected {_EXTERNAL_CONNECTION!r} in {names}"

    ca.disassociate_external_connection(
        domain=domain, repository=repo, externalConnection=_EXTERNAL_CONNECTION
    )

    # Terminal read: independent of the disassociate call that just mutated.
    described_final = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described_final.get("externalConnections", []) == [], (
        f"expected disassociation to remove the connection, got {described_final.get('externalConnections')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
