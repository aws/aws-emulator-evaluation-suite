"""cis-scan-configuration-create-list-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cis-scan-configuration-create-list-delete-lifecycle"
GROUP = "state"
SERVICES = ["inspector2"]

_RESOURCE_TYPE = "EC2"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:inspector2")
def run(ctx) -> None:
    """CreateCisScanConfiguration is visible via ListCisScanConfigurations and gone after delete."""
    inspector2 = ctx.client("inspector2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scan_name = ctx.unique_name("sim2real-cis-")

    # CIS scans require EC2 scanning to be enabled for the account first.
    original_status = _resource_status(inspector2, account_id, _RESOURCE_TYPE)

    def _restore_enablement():
        if original_status == "ENABLED":
            inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
        else:
            inspector2.disable(resourceTypes=[_RESOURCE_TYPE])

    ctx.on_cleanup(_restore_enablement)

    inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
    _poll_until(
        lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
        lambda s: s in ("ENABLED", "ENABLING"),
        timeout_s=120,
        interval_s=3,
    )

    created = _retry_until_enabled(
        lambda: inspector2.create_cis_scan_configuration(
            scanName=scan_name,
            securityLevel="LEVEL_1",
            schedule={"daily": {"startTime": {"timeOfDay": "09:00", "timezone": "UTC"}}},
            targets={
                "accountIds": [account_id],
                "targetResourceTags": {"Environment": ["sim2real-test"]},
            },
            tags={"Owner": "sim2real", "Stage": "test"},
        ),
        timeout_s=180,
        interval_s=5,
    )
    arn = created["scanConfigurationArn"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            inspector2.delete_cis_scan_configuration(scanConfigurationArn=arn)

    ctx.on_cleanup(_cleanup)

    found = _poll_until(
        lambda: _find_config(inspector2, arn),
        lambda f: f is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert found is not None, "created CIS scan configuration not found via ListCisScanConfigurations"
    assert found["scanName"] == scan_name, f"expected scanName {scan_name!r}, got {found['scanName']!r}"
    assert found["securityLevel"] == "LEVEL_1", f"expected securityLevel LEVEL_1, got {found['securityLevel']!r}"
    assert "daily" in found["schedule"], f"expected a 'daily' schedule, got {found['schedule']!r}"

    inspector2.delete_cis_scan_configuration(scanConfigurationArn=arn)
    deleted["done"] = True

    _poll_until(
        lambda: _find_config(inspector2, arn),
        lambda f: f is None,
        timeout_s=60,
        interval_s=3,
    )

    # Gone is not enough: the dead arn must also be unusable -- a second delete of the same
    # configuration must be refused with the specific not-found error, not silently accepted.
    second_delete_code, second_delete_msg = _error_code(
        lambda: inspector2.delete_cis_scan_configuration(scanConfigurationArn=arn)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected deleting an already-deleted CIS scan configuration to raise "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    assert second_delete_msg == "Resource not found.", second_delete_msg


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting an operation real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _find_config(inspector2, arn: str):
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_cis_scan_configurations(**kwargs)
        for c in resp.get("scanConfigurations", []):
            if c["scanConfigurationArn"] == arn:
                return c
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _resource_status(inspector2, account_id: str, resource_type: str) -> str:
    resp = inspector2.batch_get_account_status(accountIds=[account_id])
    accounts = resp["accounts"]
    assert len(accounts) == 1, f"expected exactly one account in response, got {len(accounts)}"
    resource_state = accounts[0]["resourceState"]
    key = "lambdaCode" if resource_type == "LAMBDA_CODE" else resource_type.lower()
    return resource_state[key]["status"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


def _retry_until_enabled(fn, *, timeout_s: float, interval_s: float):
    """Retry fn() while EC2 scanning is still transitioning from ENABLING to ENABLED."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "AccessDeniedException" and "not" in msg and "enabled" in msg.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded within {timeout_s}s while EC2 enablement settled: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
