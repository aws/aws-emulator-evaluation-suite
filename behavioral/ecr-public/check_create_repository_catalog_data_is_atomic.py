"""create-repository-catalog-data-is-atomic."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-repository-catalog-data-is-atomic"
GROUP = 'catalog-data'
SERVICES = ['ecr-public']

_DESCRIPTION_MAX = 1024  # com.amazonaws.ecrpublic#RepositoryDescription @length max
_FILLER = "SIM2REAL-SYNTHETIC-TEST-DATA-"

# RepositoryCatalogData members that are OUTPUT-only, i.e. never settable by a caller.
_OUTPUT_ONLY = {"logoUrl", "marketplaceCertified"}

# Catalog text is obviously-synthetic filler because catalog data renders publicly on
# gallery.ecr.aws.


def _err(fn):
    """Call fn(), which must fail; return its (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _filler(n: int) -> str:
    """Exactly n characters of obviously-synthetic filler."""
    return (_FILLER * (n // len(_FILLER) + 1))[:n]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An invalid catalogData.description fails CreateRepository and leaves no repository behind;
    the same call with valid catalogData then succeeds and persists the catalog data and tags.
    """
    ecr = ctx.client("ecr-public")
    name = ctx.unique_name("sim2real-behav-ecrpub-repo-")
    # Registered before either create attempt, so even a partially-created repository is reaped.
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    good_catalog = {
        "description": _filler(64),
        "architectures": ["x86-64"],
        "operatingSystems": ["Linux"],
        "aboutText": _filler(256),
        "usageText": _filler(256),
    }
    tag_pairs = [
        {"Key": "sim2real-managed", "Value": "true"},
        {"Key": "sim2real-check", "Value": CHECK},
    ]

    # --- the rejection: one member over its @length maximum ----------------------------
    bad_catalog = dict(good_catalog)
    bad_catalog["description"] = _filler(_DESCRIPTION_MAX + 1)
    code, message = _err(
        lambda: ecr.create_repository(
            repositoryName=name, catalogData=bad_catalog, tags=tag_pairs
        )
    )
    assert code == "InvalidParameterException", (
        f"CreateRepository with a {_DESCRIPTION_MAX + 1}-character description (one past the "
        f"@length max {_DESCRIPTION_MAX}) must fail with InvalidParameterException; got {code}"
    )
    assert message == (
        "Invalid parameter at 'catalogData.description' failed to satisfy constraint: "
        f"'Member must have length less than or equal to {_DESCRIPTION_MAX}'"
    ), f"InvalidParameterException message: {message!r}"

    # --- the effect is absent: no repository, not even a description-less one ----------
    account = ctx.client("sts").get_caller_identity()["Account"]
    absent, absent_message = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert absent == "RepositoryNotFoundException", (
        "the failed CreateRepository leaked a repository into the public registry; "
        f"DescribeRepositories answered {absent!r} instead of RepositoryNotFoundException. A "
        "leaked ECR Public repository is permanently world-visible on gallery.ecr.aws."
    )
    assert absent_message == (
        f"The repository with name '{name}' does not exist in the registry with id '{account}'"
    ), f"DescribeRepositories message: {absent_message!r}"

    # Same name as the failed create: a leaked repository would make this hit
    # RepositoryAlreadyExistsException.
    created = ecr.create_repository(
        repositoryName=name, catalogData=dict(good_catalog), tags=tag_pairs
    )
    assert created["repository"]["repositoryName"] == name, created
    assert "catalogData" in created, (
        "CreateRepositoryResponse models a catalogData member and must return it when catalogData "
        f"was supplied; got {sorted(created)}"
    )
    echoed = created["catalogData"]
    for field in ("description", "aboutText", "usageText"):
        assert echoed.get(field) == good_catalog[field], (
            f"CreateRepository must echo the create-time {field}; got "
            f"{echoed.get(field)!r} for a {len(good_catalog[field])}-character input"
        )
    assert echoed.get("architectures") == good_catalog["architectures"], echoed
    assert echoed.get("operatingSystems") == good_catalog["operatingSystems"], echoed
    assert "logoImageBlob" not in echoed, (
        f"logoImageBlob is input-only and must never be echoed: {sorted(echoed)}"
    )
    if "marketplaceCertified" in echoed:
        assert echoed["marketplaceCertified"] is False, (
            "a freshly created synthetic test repository cannot be Marketplace-certified; an "
            f"emulator asserting otherwise is over-permissive: {echoed['marketplaceCertified']!r}"
        )

    # --- create-time catalog data is PERSISTED, not merely echoed ---------------------
    stored = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    for field in ("description", "aboutText", "usageText"):
        assert stored.get(field) == good_catalog[field], (
            f"create-time {field} was echoed but not stored: GetRepositoryCatalogData returned "
            f"{len(stored.get(field) or '')} characters, expected {len(good_catalog[field])}"
        )
    assert stored.get("architectures") == good_catalog["architectures"], stored
    assert stored.get("operatingSystems") == good_catalog["operatingSystems"], stored
    assert "logoImageBlob" not in stored, sorted(stored)
    # No output-only member may have been treated as settable input.
    assert not (set(stored) - set(good_catalog) - _OUTPUT_ONLY), (
        f"GetRepositoryCatalogData returned unmodeled member(s) "
        f"{sorted(set(stored) - set(good_catalog) - _OUTPUT_ONLY)}"
    )
    assert "logoUrl" not in stored, (
        "no logo was uploaded, so no logoUrl may be minted; a fabricated URL would render a "
        f"broken image on the Gallery page: {stored.get('logoUrl')!r}"
    )

    # --- create-time tags are persisted too, on the repository's own ARN --------------
    arn = created["repository"]["repositoryArn"]
    listed = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    for pair in tag_pairs:
        assert listed.get(pair["Key"]) == pair["Value"], (
            f"create-time tag {pair['Key']}={pair['Value']!r} was not persisted; ListTagsForResource "
            f"returned {listed}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
