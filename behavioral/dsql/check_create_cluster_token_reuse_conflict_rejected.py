"""create-cluster-token-reuse-conflict-rejected."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-token-reuse-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a CreateCluster clientToken with different parameters fails with ConflictException and AWS's
    exact message and creates no second cluster or tag change, while the same token with the same
    parameters returns the original cluster."""
    dsql = ctx.client("dsql")
    token = ctx.unique_name("sim2real-dsql-token-")

    first = dsql.create_cluster(clientToken=token, deletionProtectionEnabled=False, tags={"sim2real-run": "first"})
    identifier = first["identifier"]
    arn = first["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    # different params (different tags) under the same token -> ConflictException
    conflict_code, conflict_message = _error(lambda: dsql.create_cluster(
        clientToken=token, deletionProtectionEnabled=False, tags={"sim2real-run": "second"},
    ))
    assert conflict_code == "ConflictException", (
        f"reusing a clientToken with DIFFERENT parameters must be rejected with ConflictException; "
        f"got {conflict_code!r}"
    )
    assert conflict_message == "Requests using a client token should supply identical request parameters", conflict_message

    # effect absent (independent read): tags on the original cluster are unchanged
    tags_after = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after.get("sim2real-run") == "first", (
        f"the rejected CreateCluster must not have altered the original cluster's tags; "
        f"expected 'first', got {tags_after!r}"
    )

    # effect absent, stronger (independent read): no second cluster was created for this token
    count_after_conflict = _cluster_count_for_arn(dsql, arn)
    assert count_after_conflict == 1, (
        f"the rejected CreateCluster must not create a second cluster for this token; "
        f"ListClusters shows {count_after_conflict} clusters matching {arn!r}"
    )

    # positive control: identical replay of the original request is accepted (idempotent)
    replay = dsql.create_cluster(clientToken=token, deletionProtectionEnabled=False, tags={"sim2real-run": "first"})
    assert replay["identifier"] == identifier, (
        f"replaying the SAME clientToken with the SAME parameters must return the original "
        f"cluster; expected identifier {identifier!r}, got {replay['identifier']!r}"
    )

    # terminal, independent read at the destination: the idempotent replay didn't create one either
    count_after_replay = _cluster_count_for_arn(dsql, arn)
    assert count_after_replay == 1, (
        f"the idempotent replay must not create a second cluster either; "
        f"ListClusters shows {count_after_replay} clusters matching {arn!r}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cluster_count_for_arn(dsql, arn):
    matches = 0
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = dsql.list_clusters(**kwargs)
        matches += sum(1 for c in page["clusters"] if c["arn"] == arn)
        next_token = page.get("nextToken")
        if not next_token:
            break
    return matches


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
