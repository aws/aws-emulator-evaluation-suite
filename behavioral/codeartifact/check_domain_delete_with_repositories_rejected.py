"""domain-delete-with-repositories-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "domain-delete-with-repositories-rejected"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomain on a domain that still contains a repository fails with ConflictException
    and leaves the domain describable; once the repository is deleted the same call succeeds."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    repo = ctx.unique_name("sim2real-behav-repo-")
    resource_tags = [{"key": "sim2real", "value": CHECK}]

    ca.create_domain(domain=domain, tags=resource_tags)
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=domain)))
    ca.create_repository(domain=domain, repository=repo, tags=resource_tags)
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_repository(domain=domain, repository=repo)))

    described = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described["name"] == repo, f"expected repository {repo!r}, got {described['name']!r}"

    # Break exactly one thing: try to delete a domain that still has a repository.
    code, message = _error(lambda: ca.delete_domain(domain=domain))[:2]
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Domain must contain 0 repositories before deletion", (
        f"the ConflictException said {message!r}, expected AWS's exact "
        f"'Domain must contain 0 repositories before deletion'"
    )

    # Effect absent: the domain is still describable.
    still_there = ca.describe_domain(domain=domain)["domain"]
    assert still_there["name"] == domain, (
        f"expected domain {domain!r} to still exist after the rejected delete, got {still_there!r}"
    )

    # Positive control: remove the repository, then the same delete succeeds.
    ca.delete_repository(domain=domain, repository=repo)
    ca.delete_domain(domain=domain)
    not_found = (
        f"Domain not found. Domain '{domain}' owned by account '{ctx.account}' does not exist."
    )
    code, message = _settled_not_found(lambda: ca.describe_domain(domain=domain))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, (
        f"DescribeDomain on the deleted domain said {message!r}, expected {not_found!r}"
    )

    # The dead domain also rejects a mutation, not just a read.
    mutate_code, mutate_message = _settled_not_found(
        lambda: ca.create_repository(domain=domain, repository=repo)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected CreateRepository on the deleted domain {domain!r} to fail with "
        f"ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_message == not_found, (
        f"CreateRepository on the deleted domain said {mutate_message!r}, expected {not_found!r}"
    )


# ===== shared helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message, response). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message"), response
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _settled_not_found(fn, timeout_s: float = 60.0, interval_s: float = 2.0):
    """(code, message) once the rejection is the settled not-found form, which carries
    ``resourceType``; right after a delete AWS briefly answers with an internal-id form."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message, response = _error(fn)
        if response.get("resourceType") or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


def _teardown(fn, timeout_s: float = 30.0) -> None:
    """Run a teardown call: done on success or ResourceNotFoundException, retried while
    ConflictException says a dependent is still being released, and raised otherwise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

