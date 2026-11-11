"""scheduling-policy-exclusive-fairshare-quotashare-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "scheduling-policy-exclusive-fairshare-quotashare-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedulingPolicy refuses fairsharePolicy with quotaSharePolicy (ClientException).

    No policy is created, and a request with only fairsharePolicy succeeds (positive control).
    """
    batch = ctx.client("batch")

    bad_name = ctx.unique_name("sim2real-batch-sp-bad-")
    code, message, request_id = _client_error(lambda: batch.create_scheduling_policy(
        name=bad_name,
        fairsharePolicy={
            "shareDecaySeconds": 0,
            "computeReservation": 0,
            "shareDistribution": [{"shareIdentifier": "a", "weightFactor": 1.0}],
        },
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
    ))
    assert code == "ClientException", f"expected ClientException for a request setting both fairsharePolicy and quotaSharePolicy, got {code!r}"
    expected = (
        "Error executing request, Exception : A scheduling policy can have either fairsharePolicy "
        f"or quotaSharePolicy, but not both., RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected request must not have created a policy under that name.
    assert not _scheduling_policy_name_exists(batch, bad_name), (
        "a scheduling policy with mutually exclusive fairsharePolicy/quotaSharePolicy "
        "was rejected but still shows up in ListSchedulingPolicies"
    )

    # Positive control: fairsharePolicy alone is accepted.
    good_name = ctx.unique_name("sim2real-batch-sp-good-")
    resp = batch.create_scheduling_policy(
        name=good_name,
        fairsharePolicy={
            "shareDecaySeconds": 0,
            "computeReservation": 0,
            "shareDistribution": [{"shareIdentifier": "a", "weightFactor": 1.0}],
        },
        tags={"sim2real": CHECK},
    )
    good_arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy(batch, good_arn))
    assert _scheduling_policy_name_exists(batch, good_name), (
        "the valid fairsharePolicy-only scheduling policy did not persist"
    )


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response.get("ResponseMetadata", {}).get("RequestId")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _scheduling_policy_name_exists(batch, name, max_pages=20):
    next_token = None
    for _ in range(max_pages):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = batch.list_scheduling_policies(**kwargs)
        for entry in resp.get("schedulingPolicies", []):
            arn = entry.get("arn", "")
            if arn.endswith(f"/{name}") or arn.endswith(f":{name}"):
                return True
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return False


def _delete_scheduling_policy(batch, arn):
    """A policy that does not exist is done; Batch's ClientException for a policy still in use is
    retried every 2 s for up to 90 s, then raised."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            batch.delete_scheduling_policy(arn=arn)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
