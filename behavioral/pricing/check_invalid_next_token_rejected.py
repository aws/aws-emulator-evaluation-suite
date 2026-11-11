"""invalid-next-token-rejected."""
from __future__ import annotations

import botocore.exceptions
from botocore.config import Config

from behavioral_harness import tags

CHECK = "invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a token real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeServices rejects a NextToken that was never issued by a previous call
    with InvalidNextTokenException, while an unpaginated call still succeeds."""
    pricing = _pricing_client(ctx)

    code, msg = _error_code(lambda: pricing.describe_services(NextToken="this-was-never-issued-by-pricing"))
    assert code == "InvalidNextTokenException", f"expected InvalidNextTokenException, got {code!r}"
    assert msg == "NextToken is invalid. ", msg

    control = pricing.describe_services(MaxResults=1)
    assert control["Services"], "positive control: DescribeServices without a token returned no services"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
