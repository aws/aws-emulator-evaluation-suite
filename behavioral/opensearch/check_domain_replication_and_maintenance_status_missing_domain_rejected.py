"""domain-replication-and-maintenance-status-missing-domain-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-replication-and-maintenance-status-missing-domain-rejected"
GROUP = "domain"
SERVICES = ["opensearch"]


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success
    raises, because accepting a call AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDomainReplication rejects a malformed DomainName with ValidationException and an
    unknown one with ResourceNotFoundException naming its ARN; GetDomainMaintenanceStatus on the
    same unknown name fails with BaseException naming the bare domain instead."""
    osc = ctx.client("opensearch")

    malformed_name = "Abc-Domain"
    malformed_refusal = _error(lambda: osc.describe_domain_replication(DomainName=malformed_name))
    expected_malformed_message = (
        f"1 validation error detected: Value '{malformed_name}' at 'domainName' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9\\-]+"
    )
    assert malformed_refusal == ("ValidationException", expected_malformed_message), (
        f"expected ValidationException with AWS's exact message for a DomainName violating the "
        f"service's pattern, got {malformed_refusal!r}"
    )

    missing = ctx.unique_name("sim2real-behav-")[:28].rstrip("-")
    replication_refusal = _error(lambda: osc.describe_domain_replication(DomainName=missing))
    expected_replication_message = (
        f"Domain not found: arn:aws:es:{ctx.region}:{ctx.account}:domain/{missing}"
    )
    assert replication_refusal == ("ResourceNotFoundException", expected_replication_message), (
        f"expected ResourceNotFoundException naming the domain's ARN for an unknown domain, got "
        f"{replication_refusal!r}"
    )

    maintenance_refusal = _error(
        lambda: osc.get_domain_maintenance_status(
            DomainName=missing, MaintenanceId=ctx.unique_name("sim2real-behav-mid-")
        )
    )
    expected_maintenance_message = f"Domain not found: {missing}"
    assert maintenance_refusal == ("BaseException", expected_maintenance_message), (
        f"expected BaseException naming the bare domain for an unknown domain, got "
        f"{maintenance_refusal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
