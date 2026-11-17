"""list-secrets-sort-by-created-date-matches-creation-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-secrets-sort-by-created-date-matches-creation-order"
GROUP = "representation"
SERVICES = ["secretsmanager"]


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _settled(probe, ok, *, timeout_s=90.0, interval_s=3.0):
    """The last observation of ``probe()`` once ``ok`` holds, else at the deadline."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not ok(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecrets SortBy=created-date orders by creation time, not by name: an exact
    ascending and descending sequence that disagrees with the lexicographic name order.
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-lscd-")
    # Suffixes chosen so creation order (z, m, a) is the REVERSE of name order (a, m, z);
    # a target that actually sorts by name here would answer the wrong sequence.
    suffixes = ["-z", "-m", "-a"]
    creation_order = []
    for suf in suffixes:
        secret_name = base + suf
        sm.create_secret(
            Name=secret_name, SecretString="sim2real-not-a-real-secret",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=secret_name: _force_delete(sm, n))
        creation_order.append(secret_name)
    name_order = sorted(creation_order)
    assert name_order != creation_order, (
        f"the fixture requires name order {name_order} to differ from creation order {creation_order}"
    )

    own_filter = [{"Key": "name", "Values": [base]}]

    def _all_by(sort_by, sort_order):
        return [
            s["Name"]
            for page in sm.get_paginator("list_secrets").paginate(
                Filters=own_filter, SortBy=sort_by, SortOrder=sort_order
            )
            for s in page["SecretList"]
        ]

    settled = _settled(lambda: _all_by("name", "asc"), lambda got: got == name_order)
    assert settled == name_order, (
        f"the 3 created secrets must converge to {name_order} under SortBy=name, got {settled}"
    )

    asc = _all_by("created-date", "asc")
    assert asc == creation_order, (
        f"SortBy=created-date SortOrder=asc must return the creation order {creation_order}, got {asc}"
    )
    desc = _all_by("created-date", "desc")
    assert desc == list(reversed(creation_order)), (
        f"SortBy=created-date SortOrder=desc must return {list(reversed(creation_order))}, got {desc}"
    )
    by_name = _all_by("name", "asc")
    assert by_name == name_order, (
        f"SortBy=name must still return the lexicographic order {name_order}, got {by_name}"
    )
    assert by_name != asc, (
        "SortBy=name and SortBy=created-date must disagree on this fixture, else the created-date "
        f"assertion above could pass by coincidence; both returned {by_name}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
