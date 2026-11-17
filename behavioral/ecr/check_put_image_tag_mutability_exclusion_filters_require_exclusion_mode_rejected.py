"""put-image-tag-mutability-exclusion-filters-require-exclusion-mode-rejected."""
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


CHECK = "put-image-tag-mutability-exclusion-filters-require-exclusion-mode-rejected"
GROUP = 'repository-settings'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutImageTagMutability with exclusion filters but a plain MUTABLE setting is rejected
    with InvalidParameterException and leaves the repository's mutability unchanged; the same
    filters with IMMUTABLE_WITH_EXCLUSION are accepted."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    filters = [{"filterType": "WILDCARD", "filter": "dev*"}]

    expected = (
        "Invalid parameter at 'imageTagMutabilityExclusionFilters' failed to satisfy "
        "constraint: 'ImageTagMutabilityExclusionFilters are not allowed when "
        "imageTagMutability is set as MUTABLE'"
    )
    code, message = _error(
        lambda: ecr.put_image_tag_mutability(
            repositoryName=name,
            imageTagMutability="MUTABLE",
            imageTagMutabilityExclusionFilters=filters,
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageTagMutability"] == "MUTABLE", (
        f"expected the repository's default MUTABLE setting unchanged, got "
        f"{described.get('imageTagMutability')!r}"
    )
    assert "imageTagMutabilityExclusionFilters" not in described, (
        f"expected no exclusion filters stored, got {described.get('imageTagMutabilityExclusionFilters')!r}"
    )

    updated = ecr.put_image_tag_mutability(
        repositoryName=name,
        imageTagMutability="IMMUTABLE_WITH_EXCLUSION",
        imageTagMutabilityExclusionFilters=filters,
    )
    assert updated["imageTagMutability"] == "IMMUTABLE_WITH_EXCLUSION", updated
    assert updated["imageTagMutabilityExclusionFilters"] == filters, updated


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
