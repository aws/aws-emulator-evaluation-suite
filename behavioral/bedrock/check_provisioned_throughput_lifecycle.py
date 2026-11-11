"""provisioned-throughput-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-throughput-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


_ENTITLEMENT_CODES = ("ServiceQuotaExceededException", "AccessDeniedException")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A no-commitment one-unit CreateProvisionedModelThroughput either reaches InService and after
    delete reads back ResourceNotFoundException, or is refused for missing entitlement (the exact
    zero-units ServiceQuotaExceededException, or AccessDeniedException) and no throughput is listed."""
    bedrock = ctx.client("bedrock")
    model_id = _first_provisionable_model_arn(bedrock)
    provisioned_name = ctx.unique_name("sim2real-pt-")

    try:
        created = bedrock.create_provisioned_model_throughput(
            modelUnits=1,
            provisionedModelName=provisioned_name,
            modelId=model_id,
            tags=[{"key": "sim2real", "value": "provisioned-throughput-lifecycle"}],
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in _ENTITLEMENT_CODES:
            raise AssertionError(
                f"expected a no-commitment entitlement refusal ({_ENTITLEMENT_CODES}) for "
                f"{model_id!r}, got {code!r}: {e.response['Error'].get('Message')}"
            ) from e
        message = e.response["Error"].get("Message", "")
        if code == "ServiceQuotaExceededException":
            expected_message = (
                f"Your account does not currently have any no commitment model units reserved for "
                f"{model_id.rsplit('/', 1)[-1]}. Please see https://support.console.aws.amazon.com/"
                f"support/home?region={ctx.region}#/case/create?issueType=service-limit-increase "
                f"to request a service quota increase."
            )
            assert message == expected_message, (
                f"expected the no-commitment quota refusal {expected_message!r}, got {message!r}"
            )
        # message varies: the AccessDeniedException alternative has no known exact message,
        # so only its code is graded.
        listing = bedrock.list_provisioned_model_throughputs()
        matches = [
            p
            for p in listing.get("provisionedModelSummaries", [])
            if p.get("provisionedModelName") == provisioned_name
        ]
        assert matches == [], f"refused purchase {provisioned_name!r} still appears in the list: {matches!r}"
        return

    provisioned_arn = created["provisionedModelArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: bedrock.delete_provisioned_model_throughput(provisionedModelId=provisioned_arn)
        )
    )

    def _probe():
        return bedrock.get_provisioned_model_throughput(provisionedModelId=provisioned_arn)

    final = _poll_until(_probe, lambda r: r["status"] in ("InService", "Failed"), timeout_s=900.0, interval_s=15.0)
    assert final["status"] == "InService", f"provisioned throughput ended in {final['status']!r}, expected InService"

    bedrock.delete_provisioned_model_throughput(provisionedModelId=provisioned_arn)

    code, _message = _error_after_delete(
        lambda: bedrock.get_provisioned_model_throughput(provisionedModelId=provisioned_arn),
        timeout_s=60.0,
        interval_s=2.0,
    )
    # message varies: this branch runs only when a billable no-commitment purchase succeeds,
    # and no exact not-found message is known for it.
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"


def _first_provisionable_model_arn(bedrock):
    resp = bedrock.list_foundation_models(byInferenceType="PROVISIONED")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    assert summaries, (
        "no ACTIVE foundation model in this account/region supports the PROVISIONED "
        "inference type needed to purchase Provisioned Throughput"
    )
    return summaries[0]["modelArn"]


def _error_after_delete(fn, timeout_s, interval_s):
    """Call fn() until it is refused; return the (code, message). Raises if it still succeeds
    when the timeout runs out."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            err = e.response["Error"]
            return err["Code"], err.get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"expected the call to be refused within {timeout_s}s, but it kept succeeding (last={last!r})")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
