"""create-repository-invalid-name-rejected."""
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

CHECK = "create-repository-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepository with uppercase characters in the name is rejected with
    InvalidParameterException and nothing is created; the same call with a valid name succeeds."""
    ecr = ctx.client("ecr")

    good_name = ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(repositoryName=good_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=good_name, force=True))
    assert ecr.describe_repositories(repositoryNames=[good_name])["repositories"][0][
        "repositoryName"
    ] == good_name, "the positive control repository was not created"

    # botocore does not enforce the name regex client-side, so this reaches the service.
    bad_name = good_name + "-INVALID-Upper"

    invalid_name = (
        "Invalid parameter at 'repositoryName' failed to satisfy constraint: 'must satisfy "
        "regular expression '[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\\.|_|__|-+)"
        "[a-z0-9]+)*)*''"
    )
    code, message = _error(lambda: ecr.create_repository(repositoryName=bad_name))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException, got {code}"
    )
    assert message == invalid_name, f"expected message {invalid_name!r}, got {message!r}"

    nf, message = _error(lambda: ecr.describe_repositories(repositoryNames=[bad_name]))
    assert nf == "InvalidParameterException", (
        f"rejected repository appears to exist; describe returned {nf}"
    )
    assert message == invalid_name, f"expected message {invalid_name!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
