"""repository-lifecycle-create-active-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "repository-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepository yields a describable repository; after DeleteRepository, DescribeRepository
    returns ResourceNotFoundException, and a second DeleteRepository succeeds with an empty body."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    repo = ctx.unique_name("sim2real-behav-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=domain)))

    created = ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_repository(domain=domain, repository=repo)))
    assert created["name"] == repo, f"expected created repository name {repo!r}, got {created['name']!r}"
    assert created["domainName"] == domain, (
        f"expected created repository domainName {domain!r}, got {created['domainName']!r}"
    )

    described = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described["arn"] == created["arn"], (
        f"independent describe_repository read returned arn {described['arn']!r}, "
        f"expected it to match the create response's arn {created['arn']!r}"
    )
    assert described["domainName"] == domain, (
        f"expected described repository domainName {domain!r}, got {described['domainName']!r}"
    )

    ca.delete_repository(domain=domain, repository=repo)

    code, message = _settled_not_found(lambda: ca.describe_repository(domain=domain, repository=repo))
    assert code == "ResourceNotFoundException", (
        f"expected describe_repository on the deleted repo to fail with ResourceNotFoundException, "
        f"got {code!r}"
    )
    not_found = (
        f"Repository not found. Repository '{repo}' in domain '{domain}' owned by account "
        f"'{ctx.account}' does not exist."
    )
    assert message == not_found, (
        f"describe_repository on the deleted repo said {message!r}, expected {not_found!r}"
    )

    # DeleteRepository is idempotent on AWS: a second delete on the same
    # already-deleted repository does not raise ResourceNotFoundException, it succeeds
    # again with an empty body (no "repository" key). A target that raises here, or
    # that re-materializes a "repository" payload, has diverged from the real contract.
    redelete = ca.delete_repository(domain=domain, repository=repo)
    assert "repository" not in redelete, (
        f"expected the idempotent re-delete of an already-deleted repository to return an "
        f"empty body, got a 'repository' key: {redelete.get('repository')!r}"
    )


# ===== shared helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message, response). An unexpected SUCCESS raises,
    because accepting a call AWS refuses must not read as a mere error-code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message"), response
    raise AssertionError(f"expected a ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


def _settled_not_found(fn, timeout_s: float = 60.0, interval_s: float = 2.0):
    """(code, message) once the rejection is the settled not-found form, which carries
    ``resourceType``; right after a delete AWS can briefly answer with an internal-id form."""
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
