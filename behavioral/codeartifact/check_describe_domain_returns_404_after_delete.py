"""describe-domain-returns-404-after-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-domain-returns-404-after-delete"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDomain on a deleted domain returns ResourceNotFoundException, not stale
    data, and the deleted domain is also unusable: a mutation naming it fails the same
    way rather than only its own describe going stale."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()

    created = ca.create_domain(domain=domain)["domain"]
    assert created["status"] == "Active", f"expected new domain Active, got {created['status']}"

    # Positive control: domain is describable while it exists.
    described = ca.describe_domain(domain=domain)["domain"]
    assert described["name"] == domain, f"expected name {domain}, got {described['name']}"
    assert described["arn"] == created["arn"], f"expected arn {created['arn']}, got {described['arn']}"

    ca.delete_domain(domain=domain)

    # DeleteDomain is synchronous for CodeArtifact, but poll briefly to avoid
    # asserting exactly at the boundary of the transition.
    from botocore.exceptions import ClientError

    expected = (
        "ResourceNotFoundException",
        f"Domain not found. Domain '{domain}' owned by account '{ctx.account}' does not exist.",
    )
    last = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            ca.describe_domain(domain=domain)
            last = None
        except ClientError as err:
            last = (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
            if last[0] == "ResourceNotFoundException":
                break
        time.sleep(1)
    assert last == expected, f"expected {expected!r}, got {last!r}"

    # Gone must mean unusable, not just describe-stale: a mutation naming the dead
    # domain fails with the same not-found code (CreateRepository's model declares
    # ResourceNotFoundException for exactly this case).
    repo = ctx.unique_name("sim2real-ca-repo-")
    mutate = _error(lambda: ca.create_repository(domain=domain, repository=repo))
    assert mutate == expected, (
        f"expected CreateRepository against a deleted domain to be {expected!r}, got {mutate!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
