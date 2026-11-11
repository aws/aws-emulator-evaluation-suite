"""update-usage-bad-request."""
from __future__ import annotations

import email.utils
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-usage-bad-request"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises rather than
    being reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateUsage "replace" on "/remaining" works, but any other patch path is rejected with
    BadRequestException and leaves the per-key quota record unchanged (read back via GetUsage)."""
    ag = ctx.client("apigateway")

    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-usagebad-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    root_id = ag.get_resources(restApiId=api_id)["items"][0]["id"]
    ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        authorizationType="NONE", apiKeyRequired=True,
    )
    ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage_name = "sim2realusagebad"
    ag.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage_name))

    plan_id = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-apigw-plan-"),
        quota={"limit": 1000, "period": "DAY"},
        apiStages=[{"apiId": api_id, "stage": stage_name}],
        tags={"sim2real": "true"},
    )["id"]

    def _delete_usage_plan():
        # DeleteUsagePlan refuses while an API stage is still attached, so detach it first.
        ag.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage_name}"}],
        )
        ag.delete_usage_plan(usagePlanId=plan_id)

    ctx.on_cleanup(_delete_usage_plan)

    key_created = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-key-"), enabled=True, tags={"sim2real": "true"},
    )
    key_id = key_created["id"]
    key_value = key_created["value"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    # UpdateUsage validates against the server clock, so "today" comes from a response's Date
    # header rather than the local clock.
    def _aws_today():
        resp = ag.get_usage_plan(usagePlanId=plan_id)
        hdr = resp.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("date")
        if not hdr:
            raise AssertionError(f"no Date header on response: {resp}")
        return email.utils.parsedate_to_datetime(hdr).date()

    today = _aws_today().isoformat()

    def _poll_until(probe, predicate, timeout=90, interval=5, description="condition"):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval)
        raise AssertionError(f"{description} not observed within {timeout}s; last saw {last!r}")

    # GetUsage has no per-day record for a key until a request through a deployed stage creates
    # it (UpdateUsage alone does not). The key association propagates slowly, so early invokes
    # can 403; keep invoking while polling.
    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/"

    def _invoke_once():
        req = urllib.request.Request(
            invoke_url, headers={"x-api-key": key_value, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status

    def _invoke_and_wait_for_usage(timeout=150, interval=5):
        deadline = time.monotonic() + timeout
        last_exc = None
        last_report = None
        while time.monotonic() < deadline:
            try:
                _invoke_once()
            except (urllib.error.HTTPError, urllib.error.URLError) as exc:
                last_exc = exc
            last_report = ag.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
            if key_id in last_report.get("items", {}):
                return last_report
            time.sleep(interval)
        raise AssertionError(
            f"GetUsage never reported a per-day record for today after repeatedly invoking the "
            f"deployed stage for {timeout}s: last invoke error={last_exc!r}, last report={last_report!r}"
        )

    baseline_report = _invoke_and_wait_for_usage()
    baseline_used, baseline_remaining = baseline_report["items"][key_id][0]
    controlled_remaining = baseline_remaining + 250

    def _update_remaining_with_retry(value, timeout=60, interval=5):
        deadline = time.monotonic() + timeout
        last_exc = None
        while time.monotonic() < deadline:
            try:
                return ag.update_usage(
                    usagePlanId=plan_id, keyId=key_id,
                    patchOperations=[{"op": "replace", "path": "/remaining", "value": str(value)}],
                )
            except ag.exceptions.BadRequestException as exc:
                last_exc = exc
                time.sleep(interval)
        raise last_exc

    # Positive control: the one patch path UpdateUsage actually implements works and is visible
    # via an independent GetUsage read, so the account/wiring is healthy and the rejection below
    # is attributable to the bad path alone -- not to everything being denied.
    _update_remaining_with_retry(controlled_remaining)
    confirmed = _poll_until(
        lambda: ag.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today),
        lambda r: key_id in r.get("items", {}) and r["items"][key_id][0][1] == controlled_remaining,
        description="the positive control's /remaining extension reflected in GetUsage",
    )
    confirmed_used = confirmed["items"][key_id][0][0]
    assert confirmed_used == baseline_used, (
        f"the positive control's /remaining patch moved 'used' from {baseline_used} to {confirmed_used}"
    )

    # Break exactly one thing: a patch path outside UpdateUsage's supported vocabulary.
    error = _client_error(lambda: ag.update_usage(
        usagePlanId=plan_id, keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/not-a-valid-date", "value": "999"}],
    ))
    assert error.get("Code") == "BadRequestException", (
        f"expected BadRequestException for a malformed UpdateUsage patch path, got {error.get('Code')!r}"
    )
    assert error.get("Message") == (
        "Invalid patch path  '/not-a-valid-date' specified for op 'replace'. Must be one of: [/remaining]"
    ), f"expected the exact patch-path refusal message, got {error.get('Message')!r}"

    # Effect absent: the rejected patch must not have moved the per-key quota record the
    # positive control just established -- an independent read at the destination, not the
    # mutating call's own response.
    after = ag.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    assert key_id in after.get("items", {}), after
    after_used, after_remaining = after["items"][key_id][0]
    assert after_remaining == controlled_remaining, (
        f"the rejected patch changed 'remaining' from {controlled_remaining} to {after_remaining}"
    )
    assert after_used == baseline_used, (
        f"the rejected patch changed 'used' from {baseline_used} to {after_used}"
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
