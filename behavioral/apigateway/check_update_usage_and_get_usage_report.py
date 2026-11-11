"""update-usage-and-get-usage-report."""
from __future__ import annotations

import email.utils
import time
import urllib.error
import urllib.request
from datetime import timedelta

from behavioral_harness import tags

CHECK = "update-usage-and-get-usage-report"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateUsage replacing /remaining sets today's remaining quota for a usage plan key without
    changing `used`, as an independent GetUsage read shows, and a date window excluding today
    reports the plan's untouched default quota."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-usage-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        authorizationType="NONE", apiKeyRequired=True,
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "sim2realusage"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    quota_limit = 1000
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-usage-plan-"),
        quota={"limit": quota_limit, "period": "DAY"},
        apiStages=[{"apiId": api_id, "stage": stage_name}],
    )["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(apigw, plan_id, api_id, stage_name))

    key_created = apigw.create_api_key(name=ctx.unique_name("sim2real-usage-key-"), enabled=True)
    key_id = key_created["id"]
    key_value = key_created["value"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    # UpdateUsage validates dates against the service clock, so query dates come from a response's
    # Date header, not the local clock.
    def _aws_today():
        resp = apigw.get_usage_plan(usagePlanId=plan_id)
        hdr = resp.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("date")
        if not hdr:
            raise AssertionError(f"no Date header on response: {resp}")
        return email.utils.parsedate_to_datetime(hdr).date()

    def _poll_until(fn, predicate, timeout=60, interval=5):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if predicate(last):
                return last
            time.sleep(interval)
        return last

    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/"

    def _invoke_once():
        req = urllib.request.Request(
            invoke_url, headers={"x-api-key": key_value, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status

    today_date = _aws_today()
    today = today_date.isoformat()

    # Reaching the stage, even with a 403 while the association propagates, seeds today's usage record;
    # a new key/plan/stage association can take minutes, so invoke and poll GetUsage for ten minutes.
    def _touch_and_wait_for_record(timeout=600, interval=10):
        deadline = time.monotonic() + timeout
        last_report = None
        invoke_outcomes: dict = {}
        while time.monotonic() < deadline:
            try:
                outcome = _invoke_once()
            except urllib.error.HTTPError as exc:
                outcome = exc.code
            except urllib.error.URLError as exc:
                outcome = type(exc.reason).__name__
            invoke_outcomes[outcome] = invoke_outcomes.get(outcome, 0) + 1
            last_report = apigw.get_usage(
                usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today
            )
            if key_id in last_report.get("items", {}):
                return last_report
            time.sleep(interval)
        raise AssertionError(
            f"GetUsage never got a today record for the key after repeatedly touching "
            f"the deployed stage for {timeout}s (invoke outcomes {invoke_outcomes}): "
            f"last report={last_report!r}"
        )

    # boto3 exposes GetUsage's per-key usage map as "items" (the wire field is "values").
    baseline_report = _touch_and_wait_for_record()
    assert key_id in baseline_report.get("items", {}), baseline_report
    baseline_used, baseline_remaining = baseline_report["items"][key_id][0]
    assert baseline_used + baseline_remaining == quota_limit, (
        f"expected used+remaining to equal the plan's {quota_limit} quota before any "
        f"UpdateUsage extension, got used={baseline_used} remaining={baseline_remaining}"
    )

    new_remaining = baseline_remaining + 100

    # A freshly-created usage-plan/key association can take a short while to
    # become visible to the UpdateUsage backend, so retry the BadRequestException
    # for a bounded window rather than a fixed sleep.
    def _update_remaining_with_retry(timeout=60, interval=5):
        deadline = time.monotonic() + timeout
        last_exc = None
        while time.monotonic() < deadline:
            try:
                return apigw.update_usage(
                    usagePlanId=plan_id,
                    keyId=key_id,
                    patchOperations=[
                        {"op": "replace", "path": "/remaining", "value": str(new_remaining)}
                    ],
                )
            except apigw.exceptions.BadRequestException as exc:
                last_exc = exc
                time.sleep(interval)
        raise last_exc

    _update_remaining_with_retry()

    # UpdateUsage's response may omit the patched value although the write succeeded, so the effect is
    # asserted on GetUsage with a bounded poll for its refresh lag.
    report = _poll_until(
        lambda: apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today),
        lambda r: key_id in r.get("items", {}) and r["items"][key_id][0][1] == new_remaining,
        timeout=60,
        interval=5,
    )
    assert key_id in report.get("items", {}), report
    used, remaining = report["items"][key_id][0]
    assert remaining == new_remaining, (
        f"expected remaining={new_remaining} for today after UpdateUsage's extension, got {remaining}"
    )
    assert used == baseline_used, (
        f"expected used={baseline_used} for today (unchanged by the /remaining patch), got {used} "
        f"in {report['items'][key_id]}"
    )

    # A window that excludes today must reflect the plan's default full quota, not
    # the extension we just granted for today's record.
    day_before = (today_date - timedelta(days=2)).isoformat()
    two_before = (today_date - timedelta(days=3)).isoformat()
    old_report = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=two_before, endDate=day_before)
    if key_id in old_report.get("items", {}):
        for used_old, remaining_old in old_report["items"][key_id]:
            assert used_old == 0
            assert remaining_old == quota_limit, (
                f"unrelated date must report the default full quota ({quota_limit}), got {remaining_old}"
            )


def _delete_usage_plan(apigw, plan_id, api_id, stage_name):
    """DeleteUsagePlan is refused while the plan still has API stages, so detach the stage first."""
    from botocore.exceptions import ClientError

    try:
        apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage_name}"}],
        )
        apigw.delete_usage_plan(usagePlanId=plan_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
