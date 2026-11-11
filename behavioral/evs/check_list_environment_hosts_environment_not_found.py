"""list-environment-hosts-environment-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-environment-hosts-environment-not-found"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEnvironmentHosts on a well-formed but nonexistent environmentId raises
    ResourceNotFoundException with its exact message, while GetVersions returns vcfVersions."""
    evs = ctx.client("evs")

    versions = evs.get_versions()["vcfVersions"]
    assert versions, f"GetVersions returned no vcfVersions; evs API is unreachable: {versions!r}"

    code, message = _error(
        lambda: evs.list_environment_hosts(environmentId="env-0000000000")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Environment env-0000000000 was not found", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
