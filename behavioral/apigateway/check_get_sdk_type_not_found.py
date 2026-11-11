"""get-sdk-type-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sdk-type-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) on a ClientError. An unexpected SUCCESS raises,
    because a target that accepts an id real AWS rejects is the strongest signal available and
    must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSdkType returns a registered SDK type (positive control) and fails with
    NotFoundException for an id outside the enumerated set, not a degraded success."""
    ag = ctx.client("apigateway")

    real_ids = {item["id"] for item in ag.get_sdk_types()["items"]}
    assert real_ids, "GetSdkTypes returned an empty catalog"

    known_id = next(iter(real_ids))
    resp = ag.get_sdk_type(id=known_id)
    assert resp["id"] == known_id, f"expected GetSdkType({known_id!r}) to resolve, got {resp!r}"

    bogus_id = "sim2real-not-a-real-sdktype"
    assert bogus_id not in real_ids, f"unlucky: {bogus_id!r} is a real sdkType id"
    code, message = _error(lambda: ag.get_sdk_type(id=bogus_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for an unsupported sdkType id, got {code}"
    )
    assert message == f"No SDK generator for '{bogus_id}'", f"unexpected message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
