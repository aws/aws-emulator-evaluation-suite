"""repository-catalog-text-limits-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repository-catalog-text-limits-enforced"
GROUP = 'catalog-data'
SERVICES = ['ecr-public']

# com.amazonaws.ecrpublic @length maxima. All are max-only (min 0), and botocore validates
# neither maxima nor patterns, so all three are genuinely SERVER-side rejections reachable from
# the SDK — unlike the min-length cases, which botocore refuses client-side.
_DESCRIPTION_MAX = 1024   # RepositoryDescription
_ABOUT_MAX = 25600        # AboutText
_USAGE_MAX = 25600        # UsageText

# Obviously-synthetic filler. Catalog data renders publicly on gallery.ecr.aws, so every byte
# written by this check must be meaningless test text and nothing else.
_FILLER = "SIM2REAL-SYNTHETIC-TEST-DATA-"


def _filler(n: int) -> str:
    """Exactly n characters of obviously-synthetic filler."""
    return (_FILLER * (n // len(_FILLER) + 1))[:n]


def _err(fn):
    """Call fn(); return the botocore Error (Code and Message) if a ClientError is raised. An
    unexpected SUCCESS raises, so a target that accepts what AWS refuses cannot read as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    tags = kwargs.pop(
        "tags",
        [{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    resp = ecr.create_repository(repositoryName=name, tags=tags, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Catalog description, aboutText and usageText round-trip verbatim at their modeled maxima, and
    one character past each is rejected with InvalidParameterException, leaving stored data intact.
    """
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    at_limit = {
        "description": _filler(_DESCRIPTION_MAX),
        "aboutText": _filler(_ABOUT_MAX),
        "usageText": _filler(_USAGE_MAX),
    }
    assert len(at_limit["description"]) == _DESCRIPTION_MAX
    assert len(at_limit["aboutText"]) == _ABOUT_MAX
    assert len(at_limit["usageText"]) == _USAGE_MAX

    # --- at the limit: accepted and echoed verbatim ------------------------------------
    put = ecr.put_repository_catalog_data(repositoryName=name, catalogData=dict(at_limit))
    echoed = put["catalogData"]
    for field, value in at_limit.items():
        assert echoed.get(field) == value, (
            f"PutRepositoryCatalogData must echo {field} verbatim at its {len(value)}-character "
            f"maximum; got {len(echoed.get(field) or '')} characters"
        )

    stored = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    for field, value in at_limit.items():
        assert stored.get(field) == value, (
            f"{field} did not round-trip verbatim at {len(value)} characters: stored "
            f"{len(stored.get(field) or '')} characters"
        )

    # --- one character past each limit: rejected, and nothing changes ------------------
    for field, limit in (
        ("description", _DESCRIPTION_MAX),
        ("aboutText", _ABOUT_MAX),
        ("usageText", _USAGE_MAX),
    ):
        over = dict(at_limit)
        over[field] = _filler(limit + 1)
        error = _err(
            lambda payload=over: ecr.put_repository_catalog_data(
                repositoryName=name, catalogData=payload
            )
        )
        assert error["Code"] == "InvalidParameterException", (
            f"{field} at {limit + 1} characters is one past its @length max {limit} and must be "
            f"rejected with InvalidParameterException; got {error!r}"
        )
        expected = (
            f"Invalid parameter at 'catalogData.{field}' failed to satisfy constraint: "
            f"'Member must have length less than or equal to {limit}'"
        )
        assert error["Message"] == expected, f"{field}: {error['Message']!r} != {expected!r}"
        # Effect absent: the rejected write must not have partially applied.
        after = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
        assert after.get(field) == at_limit[field], (
            f"the rejected over-limit {field} write mutated stored state: stored "
            f"{len(after.get(field) or '')} characters, expected {limit}"
        )
        assert after == stored, (
            f"the rejected over-limit {field} write changed some other catalog member: "
            f"{sorted(k for k in set(after) | set(stored) if after.get(k) != stored.get(k))}"
        )

    # --- control: the same call with in-limit text still succeeds ----------------------
    control = {
        "description": _filler(64),
        "aboutText": _filler(128),
        "usageText": _filler(128),
    }
    ecr.put_repository_catalog_data(repositoryName=name, catalogData=dict(control))
    final = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    for field, value in control.items():
        assert final.get(field) == value, (
            f"control write of an in-limit {field} ({len(value)} characters) did not take effect: "
            f"{final.get(field)!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
