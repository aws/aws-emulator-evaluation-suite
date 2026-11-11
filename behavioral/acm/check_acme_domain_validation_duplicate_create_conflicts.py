"""acme-domain-validation-duplicate-create-conflicts."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-domain-validation-duplicate-create-conflicts"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateAcmeDomainValidation calls for the same domain on the same endpoint:
    exactly one wins and the other is rejected with ConflictException; no duplicate record is
    left behind."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)

    domain_name = f"{ctx.unique_name('sim2real-acmedv-').lower()}.example.com"

    def racer(_i: int) -> dict:
        try:
            resp = acm.create_acme_domain_validation(
                AcmeEndpointArn=endpoint_arn,
                DomainName=domain_name,
                PrevalidationOptions={"DnsPrevalidation": {}},
            )
            return {"ok": True, "arn": resp["AcmeDomainValidationArn"]}
        except Exception as exc:  # noqa: BLE001
            error = getattr(exc, "response", {}).get("Error", {})
            return {"ok": False, "code": error.get("Code"), "message": error.get("Message")}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(racer, range(2)))

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == 1, f"expected exactly 1 loser, got {len(failures)}: {results}"
    assert failures[0]["code"] == "ConflictException", (
        f"expected ConflictException for the losing racer, got {failures[0]['code']!r}"
    )
    assert failures[0]["message"] == f"An ACME domain validation for {domain_name} already exists.", failures[0]

    winner_arn = successes[0]["arn"]
    ctx.on_cleanup(lambda: _delete_domain_validation_quiet(ctx, winner_arn))

    # Positive control: exactly one domain validation record exists for this domain on the
    # endpoint, and it is the winning racer's ARN.
    listed = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    matches = [dv for dv in listed if dv["DomainName"] == domain_name]
    assert len(matches) == 1, f"expected exactly 1 record for domain, got {len(matches)}: {matches}"
    assert matches[0]["AcmeDomainValidationArn"] == winner_arn, (
        f"expected the listed record to be the winner {winner_arn!r}, got {matches[0]['AcmeDomainValidationArn']!r}"
    )

    # Positive control: the rejection is keyed on the (endpoint, domain) pair, not a blanket
    # "only one concurrent create at a time" limiter -- a distinct domain on the same endpoint
    # must still succeed.
    other_domain = f"{ctx.unique_name('sim2real-acmedv-ctrl-').lower()}.example.com"
    other_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=other_domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation_quiet(ctx, other_arn))
    assert other_arn != winner_arn, "control domain got the same ARN as the raced domain"


def _create_acme_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    endpoint_arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_quiet(ctx, endpoint_arn))
    return endpoint_arn


def _wait_for_endpoint_active(ctx: Any, endpoint_arn: str, timeout_s: float = 120.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] == "FAILED":
            raise AssertionError(f"ACME endpoint creation failed: {last.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint never reached ACTIVE within {timeout_s}s, last={last}")


def _delete_domain_validation_quiet(ctx: Any, dv_arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)


def _delete_endpoint_quiet(ctx: Any, endpoint_arn: str) -> None:
    acm = ctx.client("acm")
    deadline = time.monotonic() + 30
    while True:
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
