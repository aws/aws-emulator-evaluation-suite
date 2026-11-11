"""check-dns-availability-prefix-legality-and-purity."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "check-dns-availability-prefix-legality-and-purity"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']


def _availability(eb, prefix):
    """(available, code) — exactly one of the two is None. An illegal prefix may be refused with a
    4xx or reported unavailable; both are acceptable *refusals*, `Available: True` is not."""
    try:
        return eb.check_dns_availability(CNAMEPrefix=prefix)["Available"], None
    except ClientError as exc:
        return None, exc.response.get("Error", {}).get("Code")


def _assert_cname_takes(cname, prefix, region, what):
    """An environment CNAME is ``<prefix>.<region>.<service domain>``. The service domain is the
    target's own, so the prefix and region labels are matched and the rest only has to be a
    domain that repeats neither."""
    head = f"{prefix}.{region}."
    assert isinstance(cname, str) and cname.startswith(head) and len(cname) > len(head), (
        f"{what}: expected a CNAME starting with {head!r} followed by a domain, got {cname!r}")
    domain = cname[len(head):]
    assert "." in domain and prefix not in domain and region not in domain, (
        f"{what}: the CNAME must carry exactly one prefix and one region label, got {cname!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckDNSAvailability reports a fresh legal CNAME prefix available, with a region-qualified
    FullyQualifiedCNAME, on repeated calls (the query reserves nothing), and never reports a prefix with a
    leading or trailing hyphen, an underscore or 64 characters available."""
    eb = ctx.client("elasticbeanstalk")

    # --- Control: a legal, fresh prefix is available and yields a region-qualified CNAME. ---
    prefix = ctx.unique_name("sim2real-behav-eb-dns-").lower()[:50].rstrip("-")
    first = eb.check_dns_availability(CNAMEPrefix=prefix)
    assert first["Available"] is True, (
        f"a freshly generated CNAME prefix must be available, got {first!r}"
    )
    fqdn = first["FullyQualifiedCNAME"]
    _assert_cname_takes(fqdn, prefix, ctx.region, "FullyQualifiedCNAME")

    # --- 2. Purity: the query reserved nothing, so the answer is stable. ---
    second = eb.check_dns_availability(CNAMEPrefix=prefix)
    assert second["Available"] is True, (
        f"CheckDNSAvailability is a query and must not reserve the prefix; the second call for "
        f"{prefix!r} reported Available={second['Available']!r}"
    )
    assert second["FullyQualifiedCNAME"] == fqdn, (
        f"repeated CheckDNSAvailability must return the same FullyQualifiedCNAME, got "
        f"{second['FullyQualifiedCNAME']!r} then {fqdn!r}"
    )

    # --- 1. Legality: break exactly one thing per case, everything else identical to the control. ---
    # Each entry is (illegal prefix, the code AWS refuses it with): charset violations are
    # InvalidParameterValue, while the request validator catches the length first as ValidationError.
    illegal = {
        "leading-hyphen": ("-" + prefix[1:], "InvalidParameterValue"),
        "trailing-hyphen": (prefix[:-1] + "-", "InvalidParameterValue"),
        "underscore": (prefix[:-1] + "_", "InvalidParameterValue"),
        # 64 characters: one past the modeled DNSCnamePrefix max of 63.
        "over-max-length": ("a" * 64, "ValidationError"),
    }
    assert len(illegal["over-max-length"][0]) == 64, illegal["over-max-length"]

    for label, (bad_prefix, expected_code) in illegal.items():
        available, code = _availability(eb, bad_prefix)
        assert available is not True, (
            f"the illegal CNAME prefix ({label}) {bad_prefix!r} must not be reported available; "
            f"CheckDNSAvailability returned Available=True, which is the over-permissive failure "
            f"mode this check exists to catch"
        )
        if code is not None:
            assert code == expected_code, (
                f"when CheckDNSAvailability refuses the illegal prefix ({label}) {bad_prefix!r} with "
                f"an error, the code must be {expected_code}, got {code!r}"
            )
        else:
            assert available is False, (
                f"the illegal prefix ({label}) {bad_prefix!r} must be reported unavailable, got "
                f"Available={available!r}"
            )

    # --- Control still works after the refusals. ---
    again = eb.check_dns_availability(CNAMEPrefix=prefix)
    assert again["Available"] is True, (
        f"the legal prefix must still be available after the illegal ones were refused, got {again!r}"
    )
    assert again["FullyQualifiedCNAME"] == fqdn, again


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
