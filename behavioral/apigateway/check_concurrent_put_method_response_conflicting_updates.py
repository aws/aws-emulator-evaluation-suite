"""concurrent-put-method-response-conflicting-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-method-response-conflicting-updates"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutMethodResponse calls with different responseModels for the same status code leave
    exactly one MethodResponse, matching the payload of the call that succeeded; the other fails with
    ConflictException."""
    from botocore.exceptions import ClientError

    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real-behav": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    # "Empty" and "Error" are the built-in models every RestApi is provisioned with.
    variants = {
        "empty": {"application/json": "Empty"},
        "error": {"application/json": "Error"},
    }

    def _put(name: str):
        try:
            resp = apigw.put_method_response(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                statusCode="200",
                responseModels=variants[name],
            )
            return (name, "ok", resp["responseModels"], None)
        except ClientError as exc:
            return (name, "err", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_put, list(variants.keys())))

    oks = [r for r in results if r[1] == "ok"]
    errs = [r for r in results if r[1] == "err"]
    assert len(oks) == 1, f"expected exactly one winner among racing PutMethodResponse calls, got {results}"
    assert len(errs) == 1, f"expected exactly one rejected racer, got {results}"
    assert errs[0][2] == "ConflictException", (
        f"losing racer did not get ConflictException, got {errs[0][2]}"
    )
    assert errs[0][3] == "Response already exists for this resource", errs[0][3]

    winner_name, _, _, _ = oks[0]
    final = apigw.get_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert final["responseModels"] == variants[winner_name], (
        f"final MethodResponse {final['responseModels']} does not match the winning "
        f"racer's payload {variants[winner_name]} -- indicates a merged/corrupted state"
    )

    # Positive control: PutMethodResponse for a brand-new status code on the same
    # method still succeeds normally -- the rejection above is specific to the
    # duplicate status code, not a blanket failure of the operation.
    control = apigw.put_method_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="404",
        responseModels={"application/json": "Error"},
    )
    assert control["statusCode"] == "404", (
        f"expected the new-status-code control to succeed with statusCode 404, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
