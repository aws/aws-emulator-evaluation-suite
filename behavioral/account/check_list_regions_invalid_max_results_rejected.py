"""list-regions-invalid-max-results-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-regions-invalid-max-results-rejected"
GROUP = "overly-permissive"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRegions with a MaxResults outside [1, 50], sent past client-side validation, is rejected
    by the service with ValidationException, while the boundary value 50 succeeds."""
    account = ctx.client("account")

    # Positive control: the account and credentials are otherwise healthy for this call.
    control = account.list_regions(MaxResults=50)
    assert len(control["Regions"]) <= 50
    assert len(control["Regions"]) >= 1

    raw = ctx.client("account", config=Config(parameter_validation=False))

    over = _error(lambda: raw.list_regions(MaxResults=51))
    over_msg = "[numeric instance is greater than the required maximum (maximum: 50, found: 51)]"
    assert over == ("ValidationException", over_msg), over

    zero = _error(lambda: raw.list_regions(MaxResults=0))
    zero_msg = "[numeric instance is lower than the required minimum (minimum: 1, found: 0)]"
    assert zero == ("ValidationException", zero_msg), zero


def _error(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a rejection, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
