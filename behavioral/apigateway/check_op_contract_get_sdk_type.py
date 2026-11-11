"""op-contract-getSdkType."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getSdkType"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSdkType returns metadata for a real, currently-registered built-in
    SDK type id; a lookup of an unknown sdk type id 404s."""
    apigw = ctx.client("apigateway")

    # The set of built-in SDK generators is account/region dependent (e.g.
    # "javascript" is not registered as a generator in every account), so
    # discover a real, currently-supported type id from GetSdkTypes rather
    # than assuming a specific hardcoded id exists.
    listing = apigw.get_sdk_types()
    assert listing["items"], "expected at least one built-in SDK type"
    known_id = listing["items"][0]["id"]

    got = apigw.get_sdk_type(id=known_id)
    assert got["id"] == known_id, f"expected id {known_id!r}, got {got['id']!r}"
    assert isinstance(got["friendlyName"], str) and len(got["friendlyName"]) > 0, (
        f"expected a non-empty friendlyName string, got {got.get('friendlyName')!r}"
    )
    assert isinstance(got["configurationProperties"], list), (
        f"expected configurationProperties to be a list, got {type(got.get('configurationProperties'))!r}"
    )

    code, message = _error(lambda: apigw.get_sdk_type(id="not-a-real-sdk-type"))
    assert code == "NotFoundException", f"expected NotFoundException for an unknown sdk type id, got {code}"
    assert message == "No SDK generator for 'not-a-real-sdk-type'", f"unexpected message: {message!r}"


def _error(fn) -> Any:
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected an unknown sdk type id to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
