"""documentation-version-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "documentation-version-ordering"
GROUP = "ordering"
SERVICES = ["apigateway"]

_COUNT = 4


def _retrying(fn, *, max_attempts: int = 8, base_delay: float = 2.0):
    """Call fn(), retrying with exponential backoff on TooManyRequestsException.

    API Gateway's control-plane API enforces a low account-level steady-state
    throttle (well below what a tight creation loop can produce), so real AWS
    can reject a burst of CreateDocumentationVersion calls with
    TooManyRequestsException even though each call is individually valid.
    """
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            attempt += 1
            if code != "TooManyRequestsException" or attempt >= max_attempts:
                raise
            time.sleep(base_delay * attempt)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Multiple CreateDocumentationVersion entries are returned in creation order via GetDocumentationVersions."""
    apigw = ctx.client("apigateway")

    api_id = _retrying(
        lambda: apigw.create_rest_api(
            name=ctx.unique_name("sim2real-docorder-"),
            endpointConfiguration={"types": ["REGIONAL"]},
            tags={"sim2real": CHECK},
        )
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    _retrying(
        lambda: apigw.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties=json.dumps({"description": "root"}),
        )
    )

    expected_versions = []
    for i in range(_COUNT):
        version = f"v{i}"
        _retrying(
            lambda version=version, i=i: apigw.create_documentation_version(
                restApiId=api_id, documentationVersion=version, description=f"sim2real-doc-{i}"
            )
        )
        expected_versions.append(version)
        time.sleep(1.0)

    full_items = _retrying(lambda: apigw.get_documentation_versions(restApiId=api_id))["items"]
    full_versions = [item["version"] for item in full_items]
    assert full_versions == expected_versions, f"expected {expected_versions}, got {full_versions}"

    collected = []
    kwargs = {"restApiId": api_id, "limit": 2}
    while True:
        resp = _retrying(lambda kwargs=kwargs: apigw.get_documentation_versions(**kwargs))
        collected.extend(item["version"] for item in resp["items"])
        token = resp.get("position")
        if not token:
            break
        kwargs["position"] = token
    assert collected == expected_versions, (
        f"paginated order {collected} != creation order {expected_versions}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
