"""op-contract-listTagsForResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource reflects tags set at creation and tags added
    afterwards via TagResource; a well-formed but nonexistent workgroup ARN
    raises ResourceNotFoundException."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "env", "Value": "test"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    wg_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg}"

    tags1 = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]}
    assert tags1 == {"env": "test"}, f"expected creation-time tags {{'env': 'test'}}, got {tags1}"

    athena.tag_resource(ResourceARN=wg_arn, Tags=[{"Key": "team", "Value": "data"}])
    tags2 = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]}
    assert tags2 == {"env": "test", "team": "data"}, f"expected merged tags after TagResource, got {tags2}"

    missing_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{ctx.unique_name('sim2real-missing-wg-')}"
    code, message = _error(lambda: athena.list_tags_for_resource(ResourceARN=missing_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Could not find valid resource from ARN: {missing_arn}", (
        f"unexpected ListTagsForResource message: {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
