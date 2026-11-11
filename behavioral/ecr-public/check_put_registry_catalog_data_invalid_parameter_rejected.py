"""put-registry-catalog-data-invalid-parameter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-registry-catalog-data-invalid-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]

_MAX_DISPLAY_NAME_CHARS = 100  # PutRegistryCatalogData displayName max length, per
# https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_PutRegistryCatalogData.html


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """PutRegistryCatalogData with a displayName over the 100-char limit raises
    InvalidParameterException rather than accepting or silently truncating it."""
    ecrpublic = _ecrpublic(ctx)
    baseline = ecrpublic.get_registry_catalog_data()["registryCatalogData"]
    baseline_name = baseline.get("displayName", "")
    ctx.on_cleanup(lambda: ecrpublic.put_registry_catalog_data(displayName=baseline_name))

    too_long = "d" * (_MAX_DISPLAY_NAME_CHARS + 1)
    error = _error(lambda: ecrpublic.put_registry_catalog_data(displayName=too_long))
    assert error["Code"] == "InvalidParameterException", (
        f"a {_MAX_DISPLAY_NAME_CHARS + 1}-character displayName must be rejected with "
        f"InvalidParameterException; got {error!r}"
    )
    expected = (
        "Invalid parameter at 'displayName' failed to satisfy constraint: "
        f"'Member must have length less than or equal to {_MAX_DISPLAY_NAME_CHARS}'"
    )
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"

    # Effect absent: the registry-level catalog record is unchanged, not partially applied
    # or silently truncated to the max length.
    after = ecrpublic.get_registry_catalog_data()["registryCatalogData"]
    assert after == baseline, (
        f"the rejected over-limit call mutated registry catalog data: {after!r} != {baseline!r}"
    )

    # Positive control: an ordinary, well-formed call to the same operation still succeeds,
    # and the terminal assertion is an independent GetRegistryCatalogData read (not the Put
    # response echo), so a target that accepts the write without durably storing it still fails.
    control_name = ctx.unique_name("sim2real-ecrpub-catalog-")[:_MAX_DISPLAY_NAME_CHARS]
    ecrpublic.put_registry_catalog_data(displayName=control_name)
    confirmed = ecrpublic.get_registry_catalog_data()["registryCatalogData"].get("displayName")
    assert confirmed == control_name, (
        f"positive-control displayName did not read back independently: {confirmed!r} != "
        f"{control_name!r}"
    )


def _error(fn) -> dict:
    """Call fn() and return the AWS Error (Code and Message). A call that SUCCEEDS raises, so an
    emulator accepting what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {result!r}")


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client pins that
    region; ctx.client keeps an emulator run on the emulator's endpoint."""
    return ctx.client("ecr-public", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

