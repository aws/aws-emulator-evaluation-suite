"""create-repository-creation-template-invalid-prefix-rejected."""
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


CHECK = "create-repository-creation-template-invalid-prefix-rejected"
GROUP = 'repository-creation-template'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepositoryCreationTemplate with an uppercase character in the prefix is rejected
    with InvalidParameterException and creates nothing; the same prefix lowercased succeeds."""
    ecr = ctx.client("ecr")

    good_prefix = ctx.unique_name("sim2real-behav-ecr-rct-")
    ecr.create_repository_creation_template(
        prefix=good_prefix, appliedFor=["PULL_THROUGH_CACHE"]
    )
    ctx.on_cleanup(lambda: ecr.delete_repository_creation_template(prefix=good_prefix))
    described = ecr.describe_repository_creation_templates(prefixes=[good_prefix])
    assert described["repositoryCreationTemplates"][0]["prefix"] == good_prefix, (
        "the positive control template was not created"
    )

    bad_prefix = good_prefix + "-INVALID"
    expected = (
        "Invalid parameter at 'prefix' failed to satisfy constraint: 'Member must satisfy "
        "regular expression pattern: ^([a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(\\/[a-z0-9]+((\\.|_|"
        "__|-+)[a-z0-9]+)*)*\\/?|ROOT)$'"
    )
    code, message = _error(
        lambda: ecr.create_repository_creation_template(
            prefix=bad_prefix, appliedFor=["PULL_THROUGH_CACHE"]
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    remaining = {
        t["prefix"]
        for t in ecr.describe_repository_creation_templates()["repositoryCreationTemplates"]
    }
    assert bad_prefix not in remaining, f"rejected prefix {bad_prefix!r} appears in the listing"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
