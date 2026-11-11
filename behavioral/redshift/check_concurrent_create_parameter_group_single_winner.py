"""concurrent-create-parameter-group-single-winner."""

from __future__ import annotations

import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-parameter-group-single-winner"
GROUP = 'overly-permissive'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

PARAMETER_GROUP_FAMILY = "redshift-1.0"
_NOT_FOUND_PARAM_GROUP = (
    "ClusterParameterGroupNotFound",
    "ClusterParameterGroupNotFoundFault",
)
_CONTENDERS = 6
# Every contender must be in flight at the same time for the race to be real; the barrier
# below is what creates the overlap. 120s is a generous bounded deadline for six threads to
# reach the barrier and is only ever hit if the harness itself is wedged.
_BARRIER_DEADLINE_S = 120


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _message_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message")
    return str(exc)


def _retrying(fn, attempts=6, delay_s=5.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _delete_parameter_group(rs, name):
    try:
        rs.delete_cluster_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if _code_of(exc) not in _NOT_FOUND_PARAM_GROUP:
            raise


def _describe_groups(rs, name):
    try:
        resp = _retrying(lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=name))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_PARAM_GROUP:
            return []
        raise
    return resp.get("ParameterGroups", [])


def _parameter_names(rs, name):
    """Every ParameterName in *name*, in the order returned, WITH duplicates preserved."""
    out = []
    marker = None
    while True:
        kwargs = {"ParameterGroupName": name, "MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_cluster_parameters(**kwargs))
        out.extend(p["ParameterName"] for p in resp.get("Parameters", []))
        marker = resp.get("Marker")
        if not marker:
            break
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateClusterParameterGroup calls for the same name produce exactly one
    winner; every loser gets ClusterParameterGroupAlreadyExists and leaves no trace in the
    surviving group's Description or parameter list."""
    rs = ctx.client("redshift")

    group = ctx.unique_name("sim2real-behav-rs-race-")
    # Registered before any contender can create it: whichever thread wins, the group is
    # cleaned up.
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, group))

    barrier = threading.Barrier(_CONTENDERS, timeout=_BARRIER_DEADLINE_S)
    outcomes = [None] * _CONTENDERS

    def contend(index):
        description = f"sim2real contender {index}"
        try:
            barrier.wait()
        except threading.BrokenBarrierError as exc:  # noqa: BLE001 - harness-level failure
            outcomes[index] = (f"EXC:{type(exc).__name__}", description, str(exc))
            return
        try:
            rs.create_cluster_parameter_group(
                ParameterGroupName=group,
                ParameterGroupFamily=PARAMETER_GROUP_FAMILY,
                Description=description,
                Tags=[{"Key": "sim2real-contender", "Value": str(index)}],
            )
        except Exception as exc:  # noqa: BLE001 - the outcome IS the observation
            outcomes[index] = (_code_of(exc), description, _message_of(exc))
            return
        outcomes[index] = ("OK", description, None)

    threads = [threading.Thread(target=contend, args=(i,)) for i in range(_CONTENDERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=_BARRIER_DEADLINE_S + 120)
    assert all(not t.is_alive() for t in threads), "a contender thread never returned"
    assert all(o is not None for o in outcomes), f"a contender recorded no outcome: {outcomes!r}"

    codes = [code for code, _, _ in outcomes]
    winners = [i for i, (code, _, _) in enumerate(outcomes) if code == "OK"]
    assert len(winners) == 1, (
        f"exactly one concurrent CreateClusterParameterGroup for {group!r} may succeed, "
        f"{len(winners)} did; outcomes={codes}"
    )
    already_exists = f"Parameter group {group} already exists"
    losers = [(code, msg) for i, (code, _, msg) in enumerate(outcomes) if i not in winners]
    unexpected = [
        (code, msg)
        for code, msg in losers
        if code != "ClusterParameterGroupAlreadyExists" or msg != already_exists
    ]
    assert not unexpected, (
        "every losing contender must be rejected with ClusterParameterGroupAlreadyExists and "
        f"the message {already_exists!r}, got {unexpected}"
    )

    # Exactly one group exists, and it is the WINNER's — not a loser's last write.
    groups = _describe_groups(rs, group)
    assert len(groups) == 1, f"expected exactly one parameter group named {group!r}, got {len(groups)}"
    surviving = groups[0]
    winner_description = outcomes[winners[0]][1]
    assert surviving["Description"] == winner_description, (
        "the surviving group must belong to the caller that got OK; expected "
        f"{winner_description!r}, got {surviving.get('Description')!r} (a loser's write landed)"
    )
    assert surviving["ParameterGroupFamily"] == PARAMETER_GROUP_FAMILY, surviving
    group_tags = surviving.get("Tags", [])
    assert len(group_tags) == 1, (
        f"the losers' tags must not be merged onto the surviving group, got {group_tags!r}"
    )
    assert group_tags[0]["Value"] == str(winners[0]), (
        f"the surviving group's tag must be the winner's, got {group_tags!r}"
    )

    # The losers did not append their parameter rows.
    names = _parameter_names(rs, group)
    assert names, f"the surviving group must expose parameters, got {names!r}"
    assert len(names) == len(set(names)), (
        "the rejected contenders must not have appended duplicate parameter rows; "
        f"{len(names)} rows for {len(set(names))} distinct names"
    )
    assert names.count("require_ssl") == 1, (
        f"require_ssl must appear exactly once, got {names.count('require_ssl')} times"
    )

    # Control (sequential): the name is now genuinely taken, and a different name is free.
    repeat, repeat_msg = "OK", None
    try:
        rs.create_cluster_parameter_group(
            ParameterGroupName=group,
            ParameterGroupFamily=PARAMETER_GROUP_FAMILY,
            Description="sim2real sequential repeat",
        )
    except Exception as exc:  # noqa: BLE001
        repeat, repeat_msg = _code_of(exc), _message_of(exc)
    assert repeat == "ClusterParameterGroupAlreadyExists", (
        f"a sequential duplicate must still be rejected, got {repeat}"
    )
    assert repeat_msg == already_exists, (
        f"expected the sequential duplicate message {already_exists!r}, got {repeat_msg!r}"
    )
    assert _describe_groups(rs, group)[0]["Description"] == winner_description, (
        "the rejected sequential duplicate must not have overwritten the Description"
    )

    other = ctx.unique_name("sim2real-behav-rs-race2-")
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, other))
    made = _retrying(
        lambda: rs.create_cluster_parameter_group(
            ParameterGroupName=other,
            ParameterGroupFamily=PARAMETER_GROUP_FAMILY,
            Description="sim2real control group",
            Tags=[{"Key": "sim2real-contender", "Value": "control"}],
        )
    )["ClusterParameterGroup"]
    assert made["ParameterGroupName"] == other, made


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
