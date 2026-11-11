"""op-contract-describeHosts."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeHosts"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeHosts returns the well-formed collection shape and rejects an unrecognized
    Dedicated Host ID."""
    ec2 = ctx.client("ec2")

    # --- success path: DescribeHosts must return the well-formed collection shape. Other checks
    # allocate and release Dedicated Hosts in the same account, so the listing is graded by its
    # shape and by the state filter selecting only what it names, never by its contents.
    resp = ec2.describe_hosts()
    assert "Hosts" in resp, f"expected a 'Hosts' key in the response, got keys {sorted(resp)}"
    assert isinstance(resp["Hosts"], list), f"expected Hosts to be a list, got {type(resp['Hosts'])!r}"
    for host in resp["Hosts"]:
        assert host.get("HostId", "").startswith("h-") and host.get("State"), (
            f"every listed Dedicated Host carries an h- HostId and a State, got {host!r}"
        )

    filtered = ec2.describe_hosts(Filter=[{"Name": "state", "Values": ["available"]}])
    off_filter = [h for h in filtered["Hosts"] if h.get("State") != "available"]
    assert off_filter == [], f"a state filter for 'available' returned other states: {off_filter!r}"

    # --- error boundary: a bogus Dedicated Host ID must be rejected --
    # (real AWS does not enforce the documented "MaxResults + HostIds" restriction here,
    # so probe with a bogus resource ID instead, which is a reliably-enforced check; real AWS
    # classifies this particular id shape as malformed rather than not-found, despite the
    # "nonexistent" framing the id's shape suggests) ---
    bogus_host_id = "h-0123456789abcdef0"

    def _call():
        ec2.describe_hosts(HostIds=[bogus_host_id])

    code, message = _error(_call)
    assert code == "InvalidHostID.Malformed", f"expected InvalidHostID.Malformed, got {code!r}"
    expected = f"The specified Dedicated host IDs ['{bogus_host_id}'] are not valid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
