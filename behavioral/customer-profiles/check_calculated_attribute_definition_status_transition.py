"""calculated-attribute-definition-status-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculated-attribute-definition-status-transition"
GROUP = "state"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created calculated attribute's readiness Status reaches COMPLETED, observed via an independent read."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = "Orders"
    attr_name = ctx.unique_name("s2r_cp_calc_").replace("-", "_")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="orders for calculated attribute",
        Fields={"Amount": {"ContentType": "NUMBER", "Source": "_source.amount", "Target": "_profile.Attributes.amount"}},
        Keys={"uniqueKey": [{"StandardIdentifiers": ["PROFILE", "UNIQUE"], "FieldNames": ["Amount"]}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )

    cp.create_calculated_attribute_definition(
        DomainName=domain,
        CalculatedAttributeName=attr_name,
        AttributeDetails={
            "Attributes": [{"Name": "Amount"}],
            "Expression": "{Orders.Amount}",
        },
        Statistic="SUM",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_calculated_attribute_definition(
                DomainName=domain, CalculatedAttributeName=attr_name
            )
        )
    )

    def _probe():
        r = cp.get_calculated_attribute_definition(
            DomainName=domain, CalculatedAttributeName=attr_name
        )
        assert r["Status"] != "FAILED", f"calculated attribute definition entered FAILED: {r!r}"
        return r

    final = _poll_until(
        _probe,
        lambda r: r["Status"] == "COMPLETED",
        timeout_s=90,
        interval_s=3,
    )
    assert final["Status"] == "COMPLETED", (
        f"expected an independent get_calculated_attribute_definition read to show Status "
        f"COMPLETED, got {final['Status']!r}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
