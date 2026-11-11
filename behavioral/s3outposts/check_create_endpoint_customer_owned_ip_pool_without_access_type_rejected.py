"""create-endpoint-customer-owned-ip-pool-without-access-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-endpoint-customer-owned-ip-pool-without-access-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3outposts"]

OUTPOST_NOT_FOUND = "The specified outpost does not exist, or does not have S3 capacity provisioned on it."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint with a CustomerOwnedIpv4Pool but no AccessType is not refused for the pairing: it
    answers the same ResourceNotFoundException and message for the unknown Outpost as a request with
    neither field, and no endpoint with that pool is listed."""
    s3o = ctx.client("s3outposts")
    outpost_id = "999999999999"
    subnet_id = "subnet-" + "0" * 8
    sg_id = "sg-" + "0" * 8
    pool = "ipv4pool-coip-" + "0" * 17

    # Baseline: neither AccessType nor CustomerOwnedIpv4Pool set -- the only thing that can
    # fail is the Outpost lookup.
    baseline_code, baseline_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId=outpost_id, SubnetId=subnet_id, SecurityGroupId=sg_id
        )
    )
    assert baseline_code == "ResourceNotFoundException", (
        f"expected the baseline request (no AccessType, no pool) to fail only on the "
        f"nonexistent Outpost, got {baseline_code!r}"
    )
    assert baseline_message == OUTPOST_NOT_FOUND, f"message={baseline_message!r}"

    # Subject: a well-formed CustomerOwnedIpv4Pool added, AccessType still unset. If the
    # service enforced the pool/AccessType pairing, this would fail earlier with
    # ValidationException instead of reaching the Outpost lookup.
    subject_code, subject_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId=outpost_id,
            SubnetId=subnet_id,
            SecurityGroupId=sg_id,
            CustomerOwnedIpv4Pool=pool,
        )
    )
    assert subject_code == baseline_code, (
        f"expected CustomerOwnedIpv4Pool without AccessType=CustomerOwnedIp to reach the same "
        f"Outpost lookup as the baseline request ({baseline_code!r}), got {subject_code!r} -- "
        f"a ValidationException here would mean the pairing is enforced"
    )
    assert subject_message == baseline_message, f"message={subject_message!r}"

    endpoints = s3o.list_endpoints(MaxResults=100)["Endpoints"]
    assert all(ep.get("CustomerOwnedIpv4Pool") != pool for ep in endpoints), (
        "no endpoint should have been created by either request"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
