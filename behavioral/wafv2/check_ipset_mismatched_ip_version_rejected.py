"""ipset-mismatched-ip-version-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ipset-mismatched-ip-version-rejected"
GROUP = "representation"
SERVICES = ["wafv2"]

_NOT_FOUND = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIPSet rejects an IPv6 CIDR in an IPV4 set with WAFInvalidParameterException and the exact
    IP_ADDRESS message and stores no IPSet; an IPv4 request round-trips, and once deleted reads as
    WAFNonexistentItemException.
    """
    wafv2 = ctx.client("wafv2")
    bad_name = ctx.unique_name("sim2real-ipset-badver-")

    code, message = _error(
        lambda: wafv2.create_ip_set(
            Name=bad_name,
            Scope="REGIONAL",
            IPAddressVersion="IPV4",
            Addresses=["2001:db8::/32"],
            Tags=[{"Key": "sim2real:check", "Value": CHECK}],
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The parameter contains formatting that is not valid., "
        "field: IP_ADDRESS, parameter: 2001:db8::/32"
    ), message

    # Effect absent: no IPSet with this name exists after the rejected create.
    listed = wafv2.list_ip_sets(Scope="REGIONAL")["IPSets"]
    assert all(s["Name"] != bad_name for s in listed), listed

    # Positive control: the same shape of request with a valid IPv4 CIDR succeeds.
    good_name = ctx.unique_name("sim2real-ipset-goodver-")
    created = wafv2.create_ip_set(
        Name=good_name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=["203.0.113.0/24"],
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["Summary"]
    ip_set_id = created["Id"]

    def _cleanup():
        # Tolerates not-found: the check deletes this IPSet itself before cleanup runs.
        from botocore.exceptions import ClientError

        try:
            lock = wafv2.get_ip_set(Name=good_name, Scope="REGIONAL", Id=ip_set_id)["LockToken"]
            wafv2.delete_ip_set(Name=good_name, Scope="REGIONAL", Id=ip_set_id, LockToken=lock)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)
    got = wafv2.get_ip_set(Name=good_name, Scope="REGIONAL", Id=ip_set_id)["IPSet"]
    assert got["Addresses"] == ["203.0.113.0/24"], f"expected round-tripped CIDR, got {got['Addresses']}"

    # The delete this check will do anyway (via cleanup) is a free negative: prove the
    # IPSet is genuinely gone and that a later read against its id fails specifically,
    # not just that DeleteIPSet's own response looked healthy.
    lock_token = wafv2.get_ip_set(Name=good_name, Scope="REGIONAL", Id=ip_set_id)["LockToken"]
    wafv2.delete_ip_set(Name=good_name, Scope="REGIONAL", Id=ip_set_id, LockToken=lock_token)
    gone_code, gone_message = _error(
        lambda: wafv2.get_ip_set(Name=good_name, Scope="REGIONAL", Id=ip_set_id)
    )
    assert gone_code == "WAFNonexistentItemException", gone_code
    assert gone_message == _NOT_FOUND, gone_message


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises, so
    an emulator accepting what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
