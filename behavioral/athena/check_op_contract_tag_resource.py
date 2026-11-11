"""op-contract-tagResource."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-tagResource"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds and upserts tags on a real workgroup, but raises ResourceNotFoundException and
    writes nothing for an ARN with no resource; once that workgroup exists, the same call succeeds."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    wg_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg}"

    athena.tag_resource(ResourceARN=wg_arn, Tags=[{"Key": "proj", "Value": "alpha"}])
    tags1 = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]}
    assert tags1 == {"proj": "alpha"}, f"expected {{'proj': 'alpha'}} after TagResource, got {tags1!r}"

    # Re-tagging the same key upserts its value rather than duplicating the tag.
    athena.tag_resource(ResourceARN=wg_arn, Tags=[{"Key": "proj", "Value": "beta"}])
    tags2 = athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]
    assert len(tags2) == 1, f"expected exactly one tag after re-tagging the same key, got {tags2!r}"
    assert tags2[0] == {"Key": "proj", "Value": "beta"}, (
        f"expected the upserted tag {{'Key': 'proj', 'Value': 'beta'}}, got {tags2[0]!r}"
    )

    # Negative: tagging a well-formed but nonexistent workgroup ARN is rejected,
    # and no tag storage is created as a side effect.
    missing_wg = ctx.unique_name("sim2real-missing-wg-")
    missing_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{missing_wg}"
    not_found = ("ResourceNotFoundException", f"Could not find valid resource from ARN: {missing_arn}")
    err = _error(
        lambda: athena.tag_resource(ResourceARN=missing_arn, Tags=[{"Key": "x", "Value": "y"}])
    )
    assert err == not_found, f"expected {not_found}, got {err}"
    err2 = _error(lambda: athena.list_tags_for_resource(ResourceARN=missing_arn))
    assert err2 == not_found, f"expected {not_found}, got {err2}"

    # Restore: creating the workgroup the ARN pointed at turns the identical call
    # valid, proving the refusal above was specifically about non-existence and
    # not, say, a malformed ARN or a permissions gap.
    athena.create_work_group(Name=missing_wg)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=missing_wg, RecursiveDeleteOption=True))
    athena.tag_resource(ResourceARN=missing_arn, Tags=[{"Key": "x", "Value": "y"}])
    tags3 = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=missing_arn)["Tags"]}
    assert tags3 == {"x": "y"}, (
        f"expected the identical TagResource call to succeed once the workgroup exists, got {tags3!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
