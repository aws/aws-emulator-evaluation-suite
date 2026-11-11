"""tls-disabled-cluster-with-a-custom-acl-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tls-disabled-cluster-with-a-custom-acl-rejected"
GROUP = 'cluster-create-rules'
SERVICES = ['memorydb']

#: A resource the target accepted and never brought to its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"
_NODE_TYPE = "db.t4g.small"
_CLUSTER_WAIT_S = 1500


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _msg(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Message", "")


def _outcome(fn) -> tuple[str, str]:
    """``("accepted", "")`` when ``fn`` succeeds, else the (code, message) it was refused with."""
    try:
        fn()
    except ClientError as exc:
        return _code(exc), _msg(exc)
    return "accepted", ""


def _poll(probe, done, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{STATE_MARKER}: {what} within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)


def _describe_cluster(mdb, name: str):
    try:
        return mdb.describe_clusters(ClusterName=name, ShowShardDetails=True)["Clusters"][0]
    except ClientError as exc:
        if _code(exc) == "ClusterNotFoundFault":
            return None
        raise


def _describe_acl(mdb, name: str):
    try:
        return mdb.describe_acls(ACLName=name)["ACLs"][0]
    except ClientError as exc:
        if _code(exc) == "ACLNotFoundFault":
            return None
        raise


def _delete_until_gone(fn, gone_code: str, busy_codes: tuple, deadline: float) -> None:
    """``fn()`` until it succeeds or reports the resource gone; a busy resource is retried."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) == gone_code:
                return
            if _code(exc) not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _delete_when_settled(mdb, name: str) -> None:
    """Delete a cluster AWS should have refused, waiting out its create first."""
    _poll(
        lambda: _describe_cluster(mdb, name),
        lambda c: c is None or c["Status"] != "creating",
        _CLUSTER_WAIT_S,
        20,
        f"wrongly accepted cluster {name} never left creating",
    )
    _delete_until_gone(
        lambda: mdb.delete_cluster(ClusterName=name),
        "ClusterNotFoundFault",
        ("InvalidClusterStateFault",),
        time.monotonic() + 300,
    )


def _create_refused(ctx, mdb, **kwargs) -> tuple[str, str]:
    """CreateCluster that must be refused: (code, message). An accepted one is deleted, then fails."""
    try:
        accepted = mdb.create_cluster(**kwargs)
    except ClientError as exc:
        return _code(exc), _msg(exc)
    ctx.on_cleanup(lambda: _delete_when_settled(mdb, kwargs["ClusterName"]))
    _delete_when_settled(mdb, kwargs["ClusterName"])
    raise AssertionError(f"CreateCluster {kwargs!r} was accepted as {accepted['Cluster']['Status']!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cluster without TLS is refused on a custom ACL, an empty one included, and DescribeClusters never
    lists it; with open-access and a missing parameter group AWS refuses for the parameter group
    instead, so the TLS-disabled open-access combination itself is accepted.
    """
    mdb = ctx.client("memorydb")
    net = ctx.network()
    base = ctx.unique_name("sim2real-mdbtl-")
    kv = [{"Key": "sim2real", "Value": CHECK}]
    user, empty = f"{base}-user", f"{base}-empty"

    mdb.create_subnet_group(
        SubnetGroupName=base, Description="sim2real", SubnetIds=net.subnet_ids, Tags=kv
    )
    ctx.on_cleanup(
        lambda: _delete_until_gone(
            lambda: mdb.delete_subnet_group(SubnetGroupName=base),
            "SubnetGroupNotFoundFault",
            ("SubnetGroupInUseFault",),
            time.monotonic() + 120,
        )
    )
    mdb.create_user(
        UserName=user,
        AccessString="on ~* &* +@all",
        AuthenticationMode={"Type": "password", "Passwords": [secrets.token_hex(24)]},
        Tags=kv,
    )
    ctx.on_cleanup(
        lambda: _delete_until_gone(
            lambda: mdb.delete_user(UserName=user),
            "UserNotFoundFault",
            ("InvalidUserStateFault",),
            time.monotonic() + 120,
        )
    )
    mdb.create_acl(ACLName=base, UserNames=[user], Tags=kv)
    ctx.on_cleanup(
        lambda: _delete_until_gone(
            lambda: mdb.delete_acl(ACLName=base),
            "ACLNotFoundFault",
            ("InvalidACLStateFault",),
            time.monotonic() + 120,
        )
    )
    mdb.create_acl(ACLName=empty, Tags=kv)
    ctx.on_cleanup(
        lambda: _delete_until_gone(
            lambda: mdb.delete_acl(ACLName=empty),
            "ACLNotFoundFault",
            ("InvalidACLStateFault",),
            time.monotonic() + 120,
        )
    )
    for acl in (base, empty):
        _poll(
            lambda a=acl: _describe_acl(mdb, a),
            lambda a: a is not None and a["Status"] == "active",
            300,
            5,
            f"ACL {acl} never became active",
        )

    common = dict(
        NodeType=_NODE_TYPE,
        Engine="valkey",
        NumShards=1,
        NumReplicasPerShard=0,
        SubnetGroupName=base,
        SecurityGroupIds=[net.security_group_id],
        TLSEnabled=False,
        SnapshotRetentionLimit=0,
        Tags=kv,
    )
    custom = ctx.unique_name("sim2real-mdbtl-c-")
    pg_name = f"{base}-absent"
    seen = {
        "custom ACL": _create_refused(ctx, mdb, ClusterName=custom, ACLName=base, **common),
        "empty ACL": _create_refused(
            ctx, mdb, ClusterName=ctx.unique_name("sim2real-mdbtl-e-"), ACLName=empty, **common
        ),
        "open-access ACL, missing parameter group": _create_refused(
            ctx,
            mdb,
            ClusterName=ctx.unique_name("sim2real-mdbtl-o-"),
            ACLName="open-access",
            ParameterGroupName=pg_name,
            **common,
        ),
        "the refused cluster": _outcome(lambda: mdb.describe_clusters(ClusterName=custom)),
    }
    want = {
        "custom ACL": (
            "InvalidParameterValueException",
            f"Custom ACL [{base}] is not supported for non TLS clusters. "
            "Supported ACLs are [open-access].",
        ),
        "empty ACL": (
            "InvalidParameterValueException",
            f"Custom ACL [{empty}] is not supported for non TLS clusters. "
            "Supported ACLs are [open-access].",
        ),
        "open-access ACL, missing parameter group": (
            "ParameterGroupNotFoundFault",
            f"ParameterGroup not found: {pg_name}",
        ),
        "the refused cluster": ("ClusterNotFoundFault", f"Cluster {custom} not found."),
    }
    assert seen == want, f"TLS-less CreateCluster answered {seen!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
