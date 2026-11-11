"""concurrent-create-cluster-duplicate-name-conflict."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-cluster-duplicate-name-conflict"
GROUP = "concurrency"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two concurrent CreateCluster calls for one clusterName, exactly one succeeds and the other fails
    with ConflictException "A cluster already exists with given name", and the winner describes under that
    (lowercased) name."""
    docdb = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-docdbe-race-")
    password = _admin_password(ctx)

    def _attempt():
        try:
            return ("ok", docdb.create_cluster(
                clusterName=name,
                authType="PLAIN_TEXT",
                adminUserName="sim2realadmin",
                adminUserPassword=password,
                shardCapacity=2,
                shardCount=1,
                tags={"sim2real-check": CHECK},
            )["cluster"])
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _attempt(), range(2)))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(errors) == 1, f"expected exactly one loser, got {len(errors)}: {results}"
    assert errors[0][0] == "ConflictException", f"expected ConflictException, got {errors[0]!r}"
    assert errors[0][1] == "A cluster already exists with given name", f"unexpected message: {errors[0]!r}"

    winner_arn = successes[0]["clusterArn"]
    _register_cluster_cleanup(ctx, winner_arn)

    # Independent read through GetCluster (not the mutating CreateCluster calls): the
    # racer that actually won is the one AWS itself now reports under this name.
    described = docdb.get_cluster(clusterArn=winner_arn)["cluster"]
    assert described["clusterName"] == name.lower(), (
        f"expected GetCluster to report clusterName {name.lower()!r} for the winning "
        f"cluster, got {described['clusterName']!r}"
    )


# ===== helpers =====
def _admin_password(ctx):
    suffix = re.sub(r"[^A-Za-z0-9]", "", ctx.unique_name("x"))[:12]
    return f"S1mparityPw{suffix}"


def _register_cluster_cleanup(ctx, arn):
    def _cleanup():
        docdb = ctx.client("docdb-elastic")
        # fits the suite's 900 s cleanup budget
        deadline = time.monotonic() + 840.0
        while time.monotonic() < deadline:
            try:
                docdb.delete_cluster(clusterArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException":
                    try:
                        status = docdb.get_cluster(clusterArn=arn)["cluster"]["status"]
                    except ClientError as err:
                        if err.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
                        return
                    if status == "STOPPED":
                        try:
                            docdb.start_cluster(clusterArn=arn)
                        except ClientError as err:
                            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                                raise
                    time.sleep(2.0)
                    continue
                raise
        raise AssertionError(f"cluster {arn} still refused DeleteCluster after 840 s")

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
