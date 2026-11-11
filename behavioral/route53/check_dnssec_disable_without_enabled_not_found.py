"""dnssec-disable-without-enabled-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dnssec-disable-without-enabled-not-found"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableHostedZoneDNSSEC on a zone with zero DNSSEC resources returns DNSSECNotFound.

    DNSSEC status is unchanged afterwards.
    """
    route53 = ctx.client("route53")
    zone_id = _create_public_hosted_zone(ctx)

    # Positive control: the zone truly has no DNSSEC resources yet.
    before = route53.get_dnssec(HostedZoneId=zone_id)
    assert before["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"expected NOT_SIGNING before any DNSSEC call, got {before['Status']['ServeSignature']!r}"
    )
    assert before.get("KeySigningKeys", []) == [], (
        f"expected no KSKs on a freshly created zone, got {before.get('KeySigningKeys')!r}"
    )

    # The zone must have no KSK at all: with an ACTIVE KSK but signing never enabled,
    # AWS treats Disable as an idempotent no-op instead of returning DNSSECNotFound.
    code, message = _error(lambda: route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id))
    assert code == "DNSSECNotFound", f"unexpected code: {code!r}"
    expected = f"Couldn't find DNSSEC information for Hosted Zone with Id '{zone_id.split('/')[-1]}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: DNSSEC status is unchanged.
    after = route53.get_dnssec(HostedZoneId=zone_id)
    assert after["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"expected NOT_SIGNING after the rejected call, got {after['Status']['ServeSignature']!r}"
    )
    assert after.get("KeySigningKeys", []) == [], (
        f"expected no KSKs after the rejected call, got {after.get('KeySigningKeys')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _unless_gone(fn, *gone: str) -> None:
    """Teardown call: return on the listed not-found codes, raise every other failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone:
            raise


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_public_hosted_zone(ctx) -> str:
    route53 = ctx.client("route53")
    name = ctx.unique_name("sim2real-r53-ksk-") + ".com."
    resp = route53.create_hosted_zone(
        Name=name, CallerReference=ctx.unique_name("sim2real-r53-cr-")
    )
    zone_id = resp["HostedZone"]["Id"].split("/")[-1]
    ctx.on_cleanup(lambda: _unless_gone(lambda: route53.delete_hosted_zone(Id=zone_id), "NoSuchHostedZone"))
    _safe(
        lambda: route53.change_tags_for_resource(
            ResourceType="hostedzone",
            ResourceId=zone_id,
            AddTags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    return zone_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
