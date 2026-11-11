"""performance-insights-retention-value-enforced."""
from __future__ import annotations

import secrets
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "performance-insights-retention-value-enforced"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PerformanceInsightsRetentionPeriod=31 is accepted and read back exactly, while 94 (not 7, 731 or a
    multiple of 31 up to 713) is rejected with InvalidParameterValue and creates no instance."""
    rds = ctx.client("rds")
    password = _rds_password()

    # --- positive control: a supported retention period is accepted and persists exactly ---
    good_id = ctx.unique_name("sim2real-rds-pi-ok-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        DBInstanceClass="db.t3.medium",
        Engine="mysql",
        MasterUsername="s2rtest",
        MasterUserPassword=password,
        AllocatedStorage=20,
        StorageType="gp2",
        PubliclyAccessible=False,
        EnablePerformanceInsights=True,
        PerformanceInsightsRetentionPeriod=31,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=good_id, SkipFinalSnapshot=True)
    )
    good_instance = _wait_for_instance_status(rds, good_id, "available", timeout_s=1200)
    assert good_instance["PerformanceInsightsEnabled"] is True, (
        f"positive control: PerformanceInsightsEnabled should be True, got "
        f"{good_instance['PerformanceInsightsEnabled']!r}"
    )
    assert good_instance["PerformanceInsightsRetentionPeriod"] == 31, (
        f"positive control: retention should persist as the requested 31, got "
        f"{good_instance['PerformanceInsightsRetentionPeriod']!r}"
    )

    # --- negative: an unsupported retention period (94 -- not 7, not 731, not month*31) ---
    bad_id = ctx.unique_name("sim2real-rds-pi-bad-")
    ctx.on_cleanup(
        lambda: _delete_instance_if_exists(rds, bad_id)
    )  # safety net if creation was not rejected
    code, message = _error(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=bad_id,
            DBInstanceClass="db.t3.medium",
            Engine="mysql",
            MasterUsername="s2rtest",
            MasterUserPassword=password,
            AllocatedStorage=20,
            StorageType="gp2",
            PubliclyAccessible=False,
            EnablePerformanceInsights=True,
            PerformanceInsightsRetentionPeriod=94,
            Tags=[{"Key": "sim2real", "Value": "true"}],
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    valid_periods = ", ".join(str(p) for p in [7, *range(31, 31 * 24, 31), 731])
    expected = f"Invalid Performance Insights retention period. Valid values are: [{valid_periods}]"
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Effect absent: the rejected call never provisioned anything (no silent rounding, no
    # partially-created instance).
    not_found_code, not_found_message = _error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_id)
    )
    assert not_found_code == "DBInstanceNotFound", (
        f"instance {bad_id} should not exist after a rejected create, got code {not_found_code!r}"
    )
    expected_not_found = f"DBInstance {bad_id} not found."
    assert not_found_message == expected_not_found, (
        f"unexpected error message: {not_found_message!r} != {expected_not_found!r}"
    )


def _rds_password() -> str:
    return "S2r" + secrets.token_hex(8)


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_instance_if_exists(rds: Any, instance_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _wait_for_instance_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    result = _poll_until(
        _probe, lambda inst: inst["DBInstanceStatus"] == status, timeout_s=timeout_s, interval_s=15
    )
    if result["DBInstanceStatus"] != status:
        raise AssertionError(
            f"instance {instance_id} never reached status {status!r} "
            f"(last: {result['DBInstanceStatus']!r})"
        )
    return result


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
