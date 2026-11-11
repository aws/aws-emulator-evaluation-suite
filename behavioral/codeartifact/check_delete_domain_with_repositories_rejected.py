"""delete-domain-with-repositories-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "delete-domain-with-repositories-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """The (code, message) of a call that MUST be rejected, the internal id masked; raises if it
    succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], _mask_internal_id(err.response["Error"].get("Message", ""))
    raise AssertionError(f"expected a ClientError, but call succeeded and returned {result!r}")


_INTERNAL_ID = re.compile(r"(repoId = '|domainId=)[0-9a-f-]{36}")


def _mask_internal_id(message: str) -> str:
    """Mask the service-internal repository or domain id, which no CodeArtifact API returns."""
    return _INTERNAL_ID.sub(r"\1<id>", message)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomain on a domain that still holds a repository fails with ConflictException
    instead of cascading the delete or silently succeeding."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()
    repo = ctx.unique_name("sim2real-ca-repo-")

    state = {"domain_deleted": False, "repo_deleted": False}

    def _cleanup_domain():
        if not state["domain_deleted"]:
            ca.delete_domain(domain=domain)

    def _cleanup_repo():
        if not state["repo_deleted"]:
            ca.delete_repository(domain=domain, repository=repo)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(_cleanup_domain)
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(_cleanup_repo)

    refusal = _error(lambda: ca.delete_domain(domain=domain))
    expected = ("ConflictException", "Domain must contain 0 repositories before deletion")
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: the domain was not deleted.
    described = ca.describe_domain(domain=domain)["domain"]
    assert described["status"] == "Active", f"expected domain still Active, got {described['status']}"

    # Positive control: once the repository is removed, deleting the domain succeeds.
    ca.delete_repository(domain=domain, repository=repo)
    state["repo_deleted"] = True
    ca.delete_domain(domain=domain)
    state["domain_deleted"] = True

    # Right after DeleteDomain, AWS words the not-found two ways: by name, or by the deleted
    # domain's internal domainId (masked; no API returns it).
    gone = {
        ("ResourceNotFoundException",
         f"Domain not found. Domain '{domain}' owned by account '{ctx.account}' does not exist."),
        ("ResourceNotFoundException", "Domain does not exist. domainId=<id>"),
    }
    after = _error(lambda: ca.describe_domain(domain=domain))
    assert after in gone, f"expected one of {sorted(gone)!r}, got {after!r}"

    # Dead id: a mutation against the deleted domain also fails, not just the read.
    mutation = _error(lambda: ca.create_repository(domain=domain, repository=repo))
    assert mutation in gone, f"expected one of {sorted(gone)!r}, got {mutation!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
