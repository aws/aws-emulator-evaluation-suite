"""concurrent-create-documentation-version-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-documentation-version-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateDocumentationVersion calls for the same version string on the
    same API: exactly one succeeds, the other is rejected with ConflictException, and only
    one documentation version ever persists (no duplicate / lost update)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-restapi-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "true"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # A documentation snapshot needs at least one documentation part to be meaningful;
    # API Gateway rejects CreateDocumentationVersion with BadRequestException otherwise.
    apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties='{"description": "sim2real behavioral check"}',
    )

    version = "v1"
    ctx.on_cleanup(
        lambda: apigw.delete_documentation_version(restApiId=api_id, documentationVersion=version)
    )

    def _create():
        return apigw.create_documentation_version(restApiId=api_id, documentationVersion=version)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        outcomes = []
        for fut in futures:
            try:
                fut.result()
                outcomes.append(("ok", None, None))
            except ClientError as exc:
                outcomes.append(("err", exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "err"]
    assert len(successes) == 1, f"nok={len(successes)} c={[o[1] for o in failures]}"
    assert len(failures) == 1, f"nok={len(successes)} c={[o[1] for o in failures]}"
    assert failures[0][1] == "ConflictException", f"got {failures[0][1]}"
    assert failures[0][2] == f"Documentation version {version} already exists.", failures[0][2]

    # Effect is not duplicated: exactly one documentation version of this name exists.
    items = apigw.get_documentation_versions(restApiId=api_id)["items"]
    matching = [i for i in items if i["version"] == version]
    assert len(matching) == 1, f"expected exactly 1 persisted documentation version, got {len(matching)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
