"""list-landing-zones-maxresults-invalid-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-landing-zones-maxresults-invalid-rejected"
GROUP = "overly-permissive"
SERVICES = ["controltower"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListLandingZones rejects maxResults=2 (the model allows only 1) with BadRequestException "Invalid
    request body", while maxResults=1 succeeds."""
    ct = ctx.client("controltower")

    code, message = _error(lambda: ct.list_landing_zones(maxResults=2))
    assert code == "BadRequestException", f"expected BadRequestException for maxResults=2, got {code}"
    assert message == "Invalid request body", (
        f"expected 'Invalid request body' for maxResults=2, got {message!r}"
    )

    # positive control: the only legal maxResults value on this operation must succeed
    ok = ct.list_landing_zones(maxResults=1)
    assert "landingZones" in ok, f"expected 'landingZones' key in response, got keys {list(ok)}"
    assert len(ok["landingZones"]) <= 1, (
        f"expected at most 1 landing zone for maxResults=1, got {len(ok['landingZones'])}"
    )


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
