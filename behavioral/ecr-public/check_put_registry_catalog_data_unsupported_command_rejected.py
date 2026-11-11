"""put-registry-catalog-data-unsupported-command-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-registry-catalog-data-unsupported-command-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """PutRegistryCatalogData from us-west-2 fails UnsupportedCommandException and leaves registry
    catalog data untouched, while the same call from us-east-1 succeeds.

    Reference: https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_PutRegistryCatalogData.html
    Reference: https://docs.aws.amazon.com/general/latest/gr/ecr-public.html
    """
    # The signing Region in each request's SigV4 credential scope tells the two clients apart.
    ecrp_east = _regional_client(ctx, "us-east-1")
    ecrp_west = _regional_client(ctx, "us-west-2")

    original = ecrp_east.get_registry_catalog_data()["registryCatalogData"].get("displayName")

    def _restore() -> None:
        if original is None:
            ecrp_east.put_registry_catalog_data(displayName="")
        else:
            ecrp_east.put_registry_catalog_data(displayName=original)

    ctx.on_cleanup(_restore)

    control_name = ctx.unique_name("sim2real-behav-")[:100]
    ecrp_east.put_registry_catalog_data(displayName=control_name)
    current = ecrp_east.get_registry_catalog_data()["registryCatalogData"].get("displayName")
    assert current == control_name, f"control update did not persist: {current!r}"

    error = _error(lambda: ecrp_west.put_registry_catalog_data(displayName="should-not-apply"))
    assert error["Code"] == "UnsupportedCommandException", (
        f"expected UnsupportedCommandException, got {error!r}"
    )
    expected = "PutRegistryCatalogData command is only supported in us-east-1."
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"

    after = ecrp_east.get_registry_catalog_data()["registryCatalogData"].get("displayName")
    assert after == control_name, f"rejected call mutated registry catalog data: {after!r}"


def _regional_client(ctx, region: str):
    """An ecr-public client signed for ``region``, built through ctx.client."""
    return ctx.client("ecr-public", region=region)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected the us-west-2 endpoint to reject with UnsupportedCommandException, "
        f"but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
