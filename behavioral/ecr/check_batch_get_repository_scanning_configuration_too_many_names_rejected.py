"""batch-get-repository-scanning-configuration-too-many-names-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "batch-get-repository-scanning-configuration-too-many-names-rejected"
GROUP = 'registry-config'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetRepositoryScanningConfiguration with 26 repository names exceeds the 25-name
    limit and is rejected with InvalidParameterException; the same call with 25 names succeeds."""
    ecr = ctx.client("ecr")

    base = ctx.unique_name("sim2real-behav-ecr-scan-")
    at_limit = [f"{base}{i}" for i in range(25)]
    ok = ecr.batch_get_repository_scanning_configuration(repositoryNames=at_limit)
    assert len(ok["failures"]) == 25, (
        f"expected all 25 names to report a failure (none exist), got {ok['failures']}"
    )

    over_limit = at_limit + [f"{base}25"]
    expected = (
        "Invalid parameter at 'repositoryNames' failed to satisfy constraint: 'Member must "
        "have length less than or equal to 25'"
    )
    code, message = _error(
        lambda: ecr.batch_get_repository_scanning_configuration(repositoryNames=over_limit)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
