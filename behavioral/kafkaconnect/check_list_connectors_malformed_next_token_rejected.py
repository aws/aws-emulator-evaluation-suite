"""list-connectors-malformed-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connectors-malformed-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectors with a nextToken that isn't a token this account ever issued is rejected."""
    kc = ctx.client("kafkaconnect")

    # Positive control first: an ordinary, unpaginated call succeeds.
    good = kc.list_connectors(maxResults=10)
    assert "connectors" in good, good

    # Break exactly one thing: pass a nextToken that was never issued by ListConnectors.
    bogus_token = "sim2real-not-a-real-pagination-token=="
    code, message = _client_error(lambda: kc.list_connectors(maxResults=10, nextToken=bogus_token))
    assert code == "BadRequestException", code
    assert message == "Invalid parameter nextToken.", message

    # Positive control (repeat, after the failed call): the API still works normally.
    good_again = kc.list_connectors(maxResults=10)
    assert "connectors" in good_again, good_again


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
