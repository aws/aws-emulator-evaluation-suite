"""concurrent-calculated-attribute-creation-exactly-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-calculated-attribute-creation-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["customer-profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Six concurrent CreateCalculatedAttributeDefinition calls with one name: exactly one succeeds, the
    rest fail with BadRequestException "... already exists", and exactly one SUM definition persists."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = "Orders"
    attr_name = ctx.unique_name("s2r_cp_race_").replace("-", "_")
    details = {"Attributes": [{"Name": "Amount"}], "Expression": "{Orders.Amount}"}
    racers = 6

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cp-dom"},
    )
    teardown = {}
    ctx.on_cleanup(lambda: _delete_domain(cp, domain, _deadline(teardown)))

    cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="orders",
        Fields={"Amount": {"ContentType": "NUMBER", "Source": "_source.amount", "Target": "_profile.Attributes.amount"}},
        Keys={"uniqueKey": [{"StandardIdentifiers": ["PROFILE", "UNIQUE"], "FieldNames": ["Amount"]}]},
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cp-ot"},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )
    ctx.on_cleanup(lambda: _delete_definition(cp, domain, attr_name, _deadline(teardown)))

    def _attempt():
        try:
            cp.create_calculated_attribute_definition(
                DomainName=domain,
                CalculatedAttributeName=attr_name,
                AttributeDetails=details,
                Statistic="SUM",
                Tags={"sim2real:managed": "true", "sim2real:prefix": "s2r_cp_race"},
            )
            return ("ok", None, None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt) for _ in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racers - 1, f"expected {racers - 1} losers, got {len(failures)}: {results}"
    assert all(code == "BadRequestException" for _, code, _ in failures), (
        f"expected every loser to be rejected with BadRequestException, got: {failures}"
    )
    expected = f"Calculated attribute definition with name {attr_name} already exists"
    assert all(message == expected for _, _, message in failures), (
        f"expected every loser's message to be {expected!r}, got: {failures}"
    )

    # terminal read at the destination, independent of the racing calls' own responses:
    # exactly one definition with this name is actually persisted, and it is the winner's.
    listed = cp.list_calculated_attribute_definitions(DomainName=domain)["Items"]
    matches = [i for i in listed if i["CalculatedAttributeName"] == attr_name]
    assert len(matches) == 1, f"expected exactly one persisted definition named {attr_name!r}, got: {matches}"

    got = cp.get_calculated_attribute_definition(DomainName=domain, CalculatedAttributeName=attr_name)
    assert got["CalculatedAttributeName"] == attr_name, got
    assert got["Statistic"] == "SUM", got


# Inside the 900 s customer-profiles cleanup budget.
_TEARDOWN_S = 600.0
# Status values of a definition still indexing historical data (ReadinessStatus).
_INDEXING = ("PREPARING", "IN_PROGRESS")


def _deadline(shared):
    """The run's teardown deadline, fixed by the first teardown that runs."""
    return shared.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _delete_domain(cp, domain, deadline):
    """Delete the domain; a 500 (InternalServerException) is retried every 2 s until ``deadline``, not-found is
    done, and any other failure or the deadline raises."""
    while True:
        try:
            cp.delete_domain(DomainName=domain)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if e.response["ResponseMetadata"].get("HTTPStatusCode") != 500 or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_definition(cp, domain, attr_name, deadline):
    """Wait every 2 s while the definition is still indexing, then delete it. DeleteCalculatedAttributeDefinition
    can answer 500 right after the race, so a 500 is retried until ``deadline``; not-found is done, and any other
    failure or the deadline raises."""
    while True:
        try:
            status = cp.get_calculated_attribute_definition(
                DomainName=domain, CalculatedAttributeName=attr_name
            ).get("Status")
            if status not in _INDEXING:
                cp.delete_calculated_attribute_definition(DomainName=domain, CalculatedAttributeName=attr_name)
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if e.response["ResponseMetadata"].get("HTTPStatusCode") != 500:
                raise
            status = "500"
        if time.monotonic() >= deadline:
            raise AssertionError(f"calculated attribute {attr_name!r} not deleted by the teardown deadline ({status})")
        time.sleep(2)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
