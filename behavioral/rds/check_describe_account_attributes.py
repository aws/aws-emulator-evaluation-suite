"""describe-account-attributes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-account-attributes"
GROUP = 'maintenance'
SERVICES = ['rds']

#: Fresh groups tried before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    """probe() once predicate holds, else the last value read at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last) or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


def _dbparametergroups_used(rds):
    resp = rds.describe_account_attributes()
    by_name = {q["AccountQuotaName"]: q for q in resp["AccountQuotas"]}
    assert "DBParameterGroups" in by_name, (
        f"expected DBParameterGroups quota in AccountQuotas, got {sorted(by_name)}"
    )
    return by_name["DBParameterGroups"]["Used"]


def _delete_parameter_group_quietly(rds, name):
    try:
        rds.delete_db_parameter_group(DBParameterGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBParameterGroupNotFound":
            raise


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountAttributes' AccountQuotas.Used is not cosmetic: creating a real
    DB parameter group must increment the reported DBParameterGroups quota's Used count
    by exactly 1, and deleting it must bring the count back down to its baseline."""
    rds = ctx.client("rds")

    # The quota's Used is account-wide, so a parameter group another run creates or deletes
    # meanwhile moves it too: each attempt round-trips a fresh group, and only a window in which
    # Used moved by exactly our own one each way is graded.
    for _ in range(_ATTEMPTS):
        used0 = _dbparametergroups_used(rds)

        group_name = ctx.unique_name("sim2real-behav-acctattr-")
        rds.create_db_parameter_group(
            DBParameterGroupName=group_name,
            DBParameterGroupFamily="mysql8.0",
            Description="sim2real behavioral audit probe",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda name=group_name: _delete_parameter_group_quietly(rds, name))

        used_after_create = _poll_until(
            lambda: _dbparametergroups_used(rds),
            lambda used, used0=used0: used == used0 + 1,
        )

        rds.delete_db_parameter_group(DBParameterGroupName=group_name)

        used_after_delete = _poll_until(
            lambda: _dbparametergroups_used(rds),
            lambda used, used0=used0: used == used0,
        )
        if used_after_create == used0 + 1 and used_after_delete == used0:
            break

    assert used_after_create == used0 + 1, (
        f"DBParameterGroups Used did not increase by exactly 1 after create "
        f"({used0} -> {used_after_create}) in the last of {_ATTEMPTS} attempts"
    )
    assert used_after_delete == used0, (
        f"DBParameterGroups Used did not return to baseline after delete "
        f"({used0} -> {used_after_delete}) in the last of {_ATTEMPTS} attempts"
    )

    try:
        resp = rds.describe_db_parameter_groups(DBParameterGroupName=group_name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, message = err.get("Code"), err.get("Message")
    else:
        raise AssertionError(f"deleted parameter group is still describable: {resp!r}")
    assert code == "DBParameterGroupNotFound", f"unexpected error code after delete: {code!r}"
    assert message == f"DBParameterGroup not found: {group_name}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
