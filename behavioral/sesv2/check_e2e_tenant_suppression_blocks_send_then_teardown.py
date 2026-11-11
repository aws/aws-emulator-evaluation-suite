"""e2e-tenant-suppression-blocks-send-then-teardown."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-tenant-suppression-blocks-send-then-teardown"
GROUP = "state-machine"
SERVICES = ["sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}

# ===== helpers =====


def _dns_baseline_domain(ctx, route53, sesv2):
    """The tagged DNS baseline domain (a public hosted zone verified in SES); an account without
    one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}; "
                    "verify it in SES before running this check"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


# ===== end helpers =====


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """A tenant-scoped suppression either is refused with the SES sandbox error and leaves nothing
    behind, or (with production access) turns SendEmail into an OnTenantSuppressionList BOUNCE;
    tenant teardown then leaves no residual tenant-resource association."""
    sesv2 = ctx.client("sesv2")

    tenant_name = ctx.unique_name("sim2real-tenant-")
    sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": "e2e-tenant-suppression"}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(ctx, tenant_name))

    # Positive control: a refusal below is then attributable to PutSuppressedDestination alone.
    sesv2.put_tenant_suppression_attributes(
        TenantName=tenant_name, SuppressionScope="TENANT", SuppressedReasons=["BOUNCE", "COMPLAINT"]
    )

    destination = f"{ctx.unique_name('sim2real-tenant-suppressed-')}@example.com"
    put_err = None
    # Without SES production access PutSuppressedDestination is always refused, while the
    # tenant calls above still succeed; the check then asserts that refusal instead of the send.
    try:
        sesv2.put_suppressed_destination(EmailAddress=destination, Reason="BOUNCE", TenantName=tenant_name)
    except ClientError as err:
        put_err = err

    if put_err is not None:
        error = put_err.response.get("Error", {})
        assert error.get("Code") == "BadRequestException", (
            f"PutSuppressedDestination failed for a reason other than the SES sandbox restriction: "
            f"{error!r}"
        )
        assert error.get("Message") == "Your account is still in the sandbox.", (
            f"expected the SES sandbox refusal message, got {error.get('Message')!r}"
        )

        not_found = _error(
            lambda: sesv2.get_suppressed_destination(EmailAddress=destination, TenantName=tenant_name)
        )
        assert not_found.get("Code") == "NotFoundException", (
            f"destination should never have entered the tenant suppression list after the refused "
            f"PutSuppressedDestination, got {not_found!r}"
        )
        not_found_message = f"Email address {destination} does not exist on your tenant suppression list."
        assert not_found.get("Message") == not_found_message, (
            f"expected message {not_found_message!r}, got {not_found.get('Message')!r}"
        )

        sesv2.delete_tenant(TenantName=tenant_name)
        _assert_tenant_gone(sesv2, tenant_name)
        return

    ctx.on_cleanup(lambda: sesv2.delete_suppressed_destination(EmailAddress=destination, TenantName=tenant_name))

    domain = _dns_baseline_domain(ctx, ctx.client("route53"), sesv2)
    identity_address = f"{ctx.unique_name('sim2real-tenantid-')}@{domain}"
    sesv2.create_email_identity(
        EmailIdentity=identity_address, Tags=[{"Key": "sim2real", "Value": "e2e-tenant-suppression"}]
    )
    ctx.on_cleanup(lambda: sesv2.delete_email_identity(EmailIdentity=identity_address))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    identity_arn = f"arn:aws:ses:{ctx.region}:{account_id}:identity/{identity_address}"

    sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=identity_arn)
    association_deleted = False

    def _safe_delete_association() -> None:
        if not association_deleted:
            try:
                sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=identity_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise

    ctx.on_cleanup(_safe_delete_association)

    content = {
        "Simple": {
            "Subject": {"Data": "sim2real tenant suppression"},
            "Body": {"Text": {"Data": "sim2real tenant suppression body"}},
        }
    }
    send_resp = sesv2.send_email(
        FromEmailAddress=identity_address,
        Destination={"ToAddresses": [destination]},
        Content=content,
        TenantName=tenant_name,
    )
    message_id = send_resp["MessageId"]
    assert message_id, "SendEmail to a tenant-suppressed destination should still be accepted"

    insights = _poll_until(
        lambda: sesv2.get_message_insights(MessageId=message_id),
        lambda resp: any(
            event.get("Type") == "BOUNCE"
            for i in resp.get("Insights", [])
            for event in i.get("Events", [])
        ),
        timeout_s=90,
        interval_s=5,
    )
    bounce_events = [
        event
        for i in insights["Insights"]
        for event in i.get("Events", [])
        if event.get("Type") == "BOUNCE"
    ]
    assert bounce_events, "no BOUNCE event recorded for the tenant-suppressed send"
    subtypes = {e.get("Details", {}).get("Bounce", {}).get("BounceSubType") for e in bounce_events}
    assert "OnTenantSuppressionList" in subtypes, (
        f"expected a BOUNCE with subtype OnTenantSuppressionList, got subtypes={subtypes}"
    )

    sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=identity_arn)
    association_deleted = True

    remaining_resources = _list_tenant_resource_arns(sesv2, tenant_name)
    assert identity_arn not in remaining_resources, "identity still associated with tenant after teardown"

    sesv2.delete_tenant(TenantName=tenant_name)
    _assert_tenant_gone(sesv2, tenant_name)


# ===== helpers =====
def _error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _assert_tenant_gone(sesv2, tenant_name: str) -> None:
    err = _error(lambda: sesv2.get_tenant(TenantName=tenant_name))
    assert err.get("Code") == "NotFoundException", f"tenant still resolvable after DeleteTenant: {err!r}"
    expected = f"The requested tenant <{tenant_name}> does not exist."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"condition never became true within {timeout_s}s (last={last!r})"
    )


def _list_tenant_resource_arns(sesv2, tenant_name: str) -> set[str]:
    arns: set[str] = set()
    token = None
    while True:
        kwargs = {"TenantName": tenant_name}
        if token:
            kwargs["NextToken"] = token
        resp = sesv2.list_tenant_resources(**kwargs)
        for res in resp.get("TenantResources", []):
            arns.add(res["ResourceArn"])
        token = resp.get("NextToken")
        if not token:
            break
    return arns


def _safe_delete_tenant(ctx, tenant_name: str) -> None:
    sesv2 = ctx.client("sesv2")
    try:
        sesv2.delete_tenant(TenantName=tenant_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
