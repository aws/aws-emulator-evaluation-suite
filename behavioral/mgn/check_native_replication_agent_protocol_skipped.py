"""native-replication-agent-protocol-skipped."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "native-replication-agent-protocol-skipped"
GROUP = "native-protocol"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Before InitializeService completes, DescribeSourceServers fails with UninitializedAccountException
    "Account not initialized" on a bare and a filtered call; on an initialized account, an actively
    replicating source server reports nonzero replicated disk sizes and a lag or snapshot signal.
    """
    mgn = ctx.client("mgn")
    try:
        server = _find_actively_replicating_source_server(mgn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "UninitializedAccountException", (
            f"DescribeSourceServers on an uninitialized account must raise "
            f"UninitializedAccountException -- this account's execution role lacks "
            f"iam:CreateServiceLinkedRole, so InitializeService can never complete and there "
            f"is no source-server data plane to reach at all -- got {code!r} instead"
        )
        assert message == "Account not initialized", (
            f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
        )
        try:
            mgn.describe_source_servers(filters={"isArchived": False})
            raise AssertionError(
                "a filtered DescribeSourceServers unexpectedly succeeded on an uninitialized "
                "account -- the account-initialization gate must apply to every call shape, "
                "not just the bare one"
            )
        except ClientError as exc2:
            code2 = exc2.response.get("Error", {}).get("Code")
            message2 = exc2.response.get("Error", {}).get("Message")
            assert code2 == "UninitializedAccountException", (
                f"a filtered DescribeSourceServers must raise the same "
                f"UninitializedAccountException as the bare call, got {code2!r}"
            )
            assert message2 == "Account not initialized", (
                f"the filtered call must answer 'Account not initialized', got {message2!r}"
            )
        return
    if server is None:
        raise AssertionError(
            "MGN's native data plane is the on-host replication agent protocol (block-level "
            "disk streaming from a real/virtual source server to an AWS-managed replication "
            "server); DescribeSourceServers found no source server with an active "
            "dataReplicationState in this account, and there is no API to provision one or "
            "install the agent -- it requires an actual machine outside this harness. Closing "
            "this gap needs a disposable VM (or emulator-side stub agent) the harness can "
            "install/launch the MGN agent on."
        )

    info = server["dataReplicationInfo"]
    state = info["dataReplicationState"]
    assert state in ("CONTINUOUS", "INITIAL_SYNC", "BACKLOG"), (
        f"an actively-replicating source server must report one of CONTINUOUS/INITIAL_SYNC/"
        f"BACKLOG, got dataReplicationState={state!r}"
    )
    disks = info.get("replicatedDisks") or []
    assert disks, "an actively replicating source server must report at least one replicated disk"
    total_bytes = sum(d.get("totalStorageBytes", 0) for d in disks)
    assert total_bytes > 0, "replicated disks must report a nonzero total storage size"
    replicated_bytes = sum(d.get("replicatedStorageBytes", 0) for d in disks)
    assert replicated_bytes <= total_bytes, (
        f"replicated bytes ({replicated_bytes}) cannot exceed the disks' total storage bytes "
        f"({total_bytes}) -- a stub that fabricates progress independently of disk size would "
        f"fail this"
    )
    # A genuine agent connection produces either a lag measurement or a snapshot timestamp;
    # a stub that merely flips the state string to CONTINUOUS would have neither.
    assert info.get("lagDuration") or info.get("lastSnapshotDateTime"), (
        "an actively replicating source server must report real replication telemetry "
        "(lagDuration or lastSnapshotDateTime), not just a bare state string"
    )


def _find_actively_replicating_source_server(mgn):
    active_states = {"CONTINUOUS", "INITIAL_SYNC", "BACKLOG"}
    next_token = None
    for _ in range(50):
        kwargs = {"nextToken": next_token} if next_token else {}
        page = mgn.describe_source_servers(**kwargs)
        for item in page.get("items", []):
            state = (item.get("dataReplicationInfo") or {}).get("dataReplicationState")
            if state in active_states:
                return item
        next_token = page.get("nextToken")
        if not next_token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
