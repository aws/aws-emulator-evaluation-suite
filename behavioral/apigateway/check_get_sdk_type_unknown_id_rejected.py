"""get-sdk-type-unknown-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sdk-type-unknown-id-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSdkType for an id absent from GetSdkTypes' catalog is rejected with NotFoundException."""
    apigw = ctx.client("apigateway")

    real_ids = {t["id"] for t in apigw.get_sdk_types()["items"]}
    assert real_ids, "GetSdkTypes returned an empty catalog"

    bogus_id = "sim2real-not-a-real-sdk-type"
    assert bogus_id not in real_ids, f"expected {bogus_id!r} to be absent from the real catalog {real_ids}"

    code, message = _error(lambda: apigw.get_sdk_type(id=bogus_id))
    assert code == "NotFoundException", f"expected NotFoundException for unknown sdk type id, got {code}"
    assert message == f"No SDK generator for '{bogus_id}'", f"unexpected message: {message!r}"

    # Positive control: a real id from the catalog resolves successfully.
    real_id = next(iter(real_ids))
    resp = apigw.get_sdk_type(id=real_id)
    assert resp["id"] == real_id, f"expected GetSdkType({real_id!r}) to echo that id, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
