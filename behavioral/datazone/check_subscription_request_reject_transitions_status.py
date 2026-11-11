"""subscription-request-reject-transitions-status."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "subscription-request-reject-transitions-status"
GROUP = "state-machine"
SERVICES = ["datazone"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectSubscriptionRequest on an ACCEPTED request is refused with ValidationException and leaves
    its status and decisionComment unchanged; DataZone auto-accepts a request that carries no
    subscription target, so the request never sits PENDING."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    producer = _create_project(ctx, domain["id"])
    consumer = _create_project(ctx, domain["id"])
    listing_id = _publish_asset_listing(ctx, domain["id"], producer["id"])

    # positive control: datazone/credentials are otherwise healthy — CreateSubscriptionRequest
    # succeeds. A plain custom asset type carries no subscription target, so DataZone auto-accepts
    # rather than leaving the request PENDING for manual review.
    request = dz.create_subscription_request(
        domainIdentifier=domain["id"],
        subscribedPrincipals=[{"project": {"identifier": consumer["id"]}}],
        subscribedListings=[{"identifier": listing_id}],
        requestReason="sim2real behavioral check subscription reject",
    )
    assert request["status"] == "ACCEPTED", (
        f"expected auto-accept for an asset with no subscription target, got {request['status']!r}"
    )

    code, message = _error(
        lambda: dz.reject_subscription_request(
            domainIdentifier=domain["id"], identifier=request["id"], decisionComment="sim2real-declined"
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException rejecting a non-PENDING request, got {code!r}"
    )
    expected = "Cannot reject a subscription request with status ACCEPTED"
    assert message == expected, (
        f"expected {expected!r} rejecting a non-PENDING request, got {message!r}"
    )

    details = dz.get_subscription_request_details(domainIdentifier=domain["id"], identifier=request["id"])
    assert details["status"] == "ACCEPTED", f"status changed after a refused reject: {details['status']!r}"
    assert details.get("decisionComment") is None, (
        f"a refused reject wrote a decisionComment: {details.get('decisionComment')!r}"
    )


# ===== helpers =====
def _safe(fn, deadline_s=60.0):
    """Teardown: a resource already gone is fine; ConflictException (a dependent resource is still
    being released) is retried to a deadline; every other error raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + deadline_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("ResourceNotFoundException", "NoSuchEntity"):
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target that
    accepts what real AWS refuses must not be reported as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last}")


def _create_domain(ctx):
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain(identifier=domain_id, cascadeDelete=True))
    )
    return _wait_domain_available(ctx, domain_id)


def _create_domain_execution_role(ctx):

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dz-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datazone.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetContext"],
            }
        ],
    }
    role = _create_role_with_retry(iam, role_name, trust_policy)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, timeout_s=60.0):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(name=name, domainExecutionRole=role_arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_domain_available(ctx, domain_id, timeout_s=900.0):
    dz = ctx.client("datazone")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = dz.get_domain(identifier=domain_id)
        last = resp
        if resp["status"] == "AVAILABLE":
            return resp
        if resp["status"] == "CREATION_FAILED":
            raise AssertionError(f"domain {domain_id} creation failed: {resp}")
        time.sleep(5)
    raise AssertionError(f"domain {domain_id} did not become AVAILABLE in time: {last}")


def _create_project(ctx, domain_id, name=None, domain_unit_id=None):
    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {"domainIdentifier": domain_id, "name": name}
    if domain_unit_id:
        kwargs["domainUnitId"] = domain_unit_id
    resp = dz.create_project(**kwargs)
    project_id = resp["id"]
    ctx.on_cleanup(
        _safe(
            lambda: dz.delete_project(
                domainIdentifier=domain_id, identifier=project_id, skipDeletionCheck=True
            )
        )
    )
    return resp


def _create_minimal_asset_type(ctx, domain_id, project_id):
    dz = ctx.client("datazone")
    resp = dz.create_asset_type(
        domainIdentifier=domain_id,
        name=ctx.unique_name("Sim2realAssetType"),
        formsInput={},
        owningProjectIdentifier=project_id,
    )
    ctx.on_cleanup(
        _safe(lambda: dz.delete_asset_type(domainIdentifier=domain_id, identifier=resp["name"]))
    )
    return resp


def _publish_asset_listing(ctx, domain_id, owning_project_id):
    dz = ctx.client("datazone")
    asset_type = _create_minimal_asset_type(ctx, domain_id, owning_project_id)
    asset = dz.create_asset(
        domainIdentifier=domain_id,
        name=ctx.unique_name("sim2real-dz-asset-"),
        typeIdentifier=asset_type["name"],
        owningProjectIdentifier=owning_project_id,
    )
    ctx.on_cleanup(_safe(lambda: dz.delete_asset(domainIdentifier=domain_id, identifier=asset["id"])))
    change_set = dz.create_listing_change_set(
        domainIdentifier=domain_id, entityIdentifier=asset["id"], entityType="ASSET", action="PUBLISH"
    )
    listing_id = change_set["listingId"]
    def _delete_listing():
        from botocore.exceptions import ClientError

        try:
            dz.delete_listing(domainIdentifier=domain_id, identifier=listing_id)
        except ClientError as exc:
            # An approved subscription blocks DeleteListing until it is revoked; _safe retries.
            blocker = re.search(r"prevented by subscription (\w+)", exc.response["Error"].get("Message", ""))
            if blocker:
                sub = dz.get_subscription(domainIdentifier=domain_id, identifier=blocker.group(1))
                if sub["status"] == "APPROVED":
                    dz.revoke_subscription(domainIdentifier=domain_id, identifier=sub["id"])
            raise

    ctx.on_cleanup(_safe(_delete_listing))
    _poll_until(
        lambda: dz.get_listing(domainIdentifier=domain_id, identifier=listing_id),
        lambda resp: resp["status"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
    )
    return listing_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
