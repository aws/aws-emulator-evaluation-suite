"""put-integration-overwrite-replaces-the-whole-configuration-not-a-merge."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-integration-overwrite-replaces-the-whole-configuration-not-a-merge"
GROUP = "methods-integrations"
SERVICES = ["apigateway"]

_DEFAULT_TIMEOUT_MS = 29000


def _delete_rest_api_quota_aware(apigw, api_id, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd to one call every 30s per account; retry the throttle."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutIntegration on the same method replaces the stored configuration wholesale:
    a field the second call omits reverts to its default rather than keeping its prior value."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-integover-"))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(apigw, api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestParameters={"integration.request.header.X-Upstream": "'first-value'"},
        requestTemplates={
            "application/json": '{"statusCode": 200}',
            "text/plain": '{"statusCode": 200}',
        },
        timeoutInMillis=15000,
    )

    before = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert before["requestParameters"] == {"integration.request.header.X-Upstream": "'first-value'"}, (
        f"expected the first PutIntegration's requestParameters to be stored, got "
        f"{before.get('requestParameters')!r}"
    )
    assert set(before["requestTemplates"]) == {"application/json", "text/plain"}, (
        f"expected both request template keys to be stored, got {sorted(before['requestTemplates'])}"
    )
    assert before["timeoutInMillis"] == 15000, (
        f"expected the first PutIntegration's timeoutInMillis to be stored, got {before.get('timeoutInMillis')!r}"
    )

    # The second call is a plain re-PUT: it restates only `type` and one requestTemplates key,
    # naming neither requestParameters nor timeoutInMillis.
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    after = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert after.get("requestParameters") in (None, {}), (
        f"expected requestParameters to be gone after the overwrite (a merge would keep "
        f"X-Upstream), got {after.get('requestParameters')!r}"
    )
    assert set(after["requestTemplates"]) == {"application/json"}, (
        f"expected only the restated requestTemplates key to survive the overwrite, got "
        f"{sorted(after['requestTemplates'])}"
    )
    assert after["timeoutInMillis"] == _DEFAULT_TIMEOUT_MS, (
        f"expected timeoutInMillis to revert to the default {_DEFAULT_TIMEOUT_MS} after the "
        f"overwrite omitted it (a merge would keep 15000), got {after.get('timeoutInMillis')!r}"
    )

    # Positive control: the surviving field is not a side effect of the assertions above —
    # an independent read agrees with what the second call actually wrote.
    reread = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert reread["requestTemplates"]["application/json"] == '{"statusCode": 200}', (
        f"expected the restated template body to read back unchanged, got "
        f"{reread['requestTemplates'].get('application/json')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
