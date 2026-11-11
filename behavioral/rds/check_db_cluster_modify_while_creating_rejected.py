"""db-cluster-modify-while-creating-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-cluster-modify-while-creating-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh clusters tried before the check gives up on observing the creating window.
_ATTEMPTS = 3
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_EXPECTED = "DB cluster isn't available for modification with status creating."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBCluster on a cluster still creating is refused with InvalidDBClusterStateFault and its
    exact message, and the refused change is not applied to the cluster."""
    rds = ctx.client("rds")
    subnet_group = _subnet_group(ctx, rds)
    tried = []
    cluster = None
    for _ in range(_ATTEMPTS):
        candidate = ctx.unique_name("sim2real-rds-cmod-")
        created = rds.create_db_cluster(
            DBClusterIdentifier=candidate, Engine="aurora-postgresql", MasterUsername="probeadmin",
            MasterUserPassword=_password(), BackupRetentionPeriod=1, StorageEncrypted=False,
            DBSubnetGroupName=subnet_group, Tags=_TAGS,
        )["DBCluster"]
        ctx.on_cleanup(lambda c=candidate: _drop(rds, c))
        assert created["Status"] == "creating", (
            f"CreateDBCluster answered Status {created['Status']!r}, expected 'creating'"
        )
        before = _cluster(rds, candidate)["Status"]
        if before != "creating":
            tried.append(f"{candidate}: read {before!r} before the modify")
            continue
        code, message = _outcome(lambda: rds.modify_db_cluster(
            DBClusterIdentifier=candidate, ApplyImmediately=True, BackupRetentionPeriod=7))
        if (code, message) == ("InvalidDBClusterStateFault", _EXPECTED):
            cluster = candidate
            break
        after = _cluster(rds, candidate)["Status"]
        assert after != "creating", (
            f"ModifyDBCluster on a creating cluster answered {code!r} {message!r}; expected "
            f"InvalidDBClusterStateFault {_EXPECTED!r}"
        )
        assert code == _ACCEPTED, f"ModifyDBCluster answered {code!r} {message!r} once the cluster was {after!r}"
        tried.append(f"{candidate}: modify accepted after the cluster left creating ({after!r})")
    assert cluster, f"ModifyDBCluster was never refused while creating in {_ATTEMPTS} clusters: {tried!r}"

    described = _cluster(rds, cluster)
    assert described["BackupRetentionPeriod"] == 1, (
        f"the refused ModifyDBCluster changed BackupRetentionPeriod to {described['BackupRetentionPeriod']!r}"
    )
    pending = described.get("PendingModifiedValues") or {}
    assert "BackupRetentionPeriod" not in pending, (
        f"the refused ModifyDBCluster left a pending change {pending!r}"
    )


def _password() -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)) + "9Aa"


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _cluster(rds, cluster: str) -> dict:
    return rds.describe_db_clusters(DBClusterIdentifier=cluster)["DBClusters"][0]


def _retry(fn, gone: str, busy: tuple[str, ...], timeout_s: float) -> None:
    """Run a delete, retrying while a ``busy`` code refuses it; ``gone`` counts as deleted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _drop(rds, cluster: str) -> None:
    """Delete the cluster, retrying while its state refuses it, and wait until it is gone."""
    _retry(lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster, SkipFinalSnapshot=True),
           "DBClusterNotFoundFault", ("InvalidDBClusterStateFault",), 1500.0)
    _gone(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster), "DBClusterNotFoundFault",
          f"DB cluster {cluster}")


def _gone(describe, gone: str, what: str, timeout_s: float = 1500.0) -> None:
    """Poll ``describe`` until it raises ``gone``; a delete accepted while creating still lists it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            describe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == gone:
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{what} still present {timeout_s:.0f}s after its delete")
        time.sleep(2)


def _subnet_group(ctx, rds) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-rds-dbsg-")
    rds.create_db_subnet_group(DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real shared network",
                               SubnetIds=ctx.network().subnet_ids, Tags=_TAGS)
    ctx.on_cleanup(lambda: _retry(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
                                  "DBSubnetGroupNotFoundFault",
                                  ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"), 1500.0))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
