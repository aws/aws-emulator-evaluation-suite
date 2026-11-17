"""data-quality-result-v2-unknown-id-lookups-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-quality-result-v2-unknown-id-lookups-rejected"
GROUP = "data-quality"
SERVICES = ["glue"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDataQualityResultV2 on a ResultId nobody published fails EntityNotFoundException,
    while BatchGetDataQualityResultV2 reports that same id in ResultsNotFound rather than
    raising, and both read back a result PublishDataQualityResultV2 really created.
    """
    glue = ctx.client("glue")
    context_name = ctx.unique_name("sim2real-behav-dq-ctx-")

    published = glue.publish_data_quality_result_v2(
        EvaluationContext=context_name,
        Score=0.75,
        Dimensions={"DimensionType": "Completeness"},
        RuleResults=[
            {"Name": "rule-1", "Result": "PASS"},
            {"Name": "rule-2", "Result": "FAIL"},
        ],
    )
    result_id = published["ResultId"]

    # A real ResultId has the shape "dqresult-<40 hex chars>"; a syntactically valid id nobody
    # published, built from this check's own context name, keeps the not-found path on-shape.
    missing_id = "dqresult-" + hashlib.sha1(context_name.encode()).hexdigest()
    code, message = _error(lambda: glue.get_data_quality_result_v2(ResultId=missing_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    expected_missing = f"Cannot find Data Quality Result in account {ctx.account} with id {missing_id}"
    assert message == expected_missing, f"unexpected message for a missing result id: {message!r}"

    # BatchGetDataQualityResultV2 does not raise for an unknown id: it reports it absent instead.
    batch = glue.batch_get_data_quality_result_v2(ResultIds=[result_id, missing_id])
    found_ids = [r["ResultId"] for r in batch["Results"]]
    assert found_ids == [result_id], f"expected only {result_id!r} in Results, got {found_ids!r}"
    assert batch["ResultsNotFound"] == [missing_id], (
        f"expected ResultsNotFound == [{missing_id!r}], got {batch['ResultsNotFound']!r}"
    )

    # Positive control: the real id reads back the result GetDataQualityResultV2 just created.
    got = glue.get_data_quality_result_v2(ResultId=result_id)
    assert got["Score"] == 0.75, f"expected Score 0.75, got {got.get('Score')!r}"
    assert got["EvaluationContext"] == context_name, (
        f"expected EvaluationContext {context_name!r}, got {got.get('EvaluationContext')!r}"
    )
    rule_results = {r["Name"]: r["Result"] for r in got["RuleResults"]}
    assert rule_results == {"rule-1": "PASS", "rule-2": "FAIL"}, (
        f"expected rule-1/rule-2 PASS/FAIL, got {rule_results!r}"
    )

    # Independent read: ListDataQualityResultsV2, filtered to this check's own EvaluationContext,
    # shows exactly the one result it published under that context.
    pages = glue.get_paginator("list_data_quality_results_v2").paginate(
        Filter={"EvaluationContext": context_name}
    )
    listed_ids = {r["ResultId"] for page in pages for r in page["Results"]}
    assert listed_ids == {result_id}, (
        f"expected ListDataQualityResultsV2 under EvaluationContext={context_name!r} to show only "
        f"{result_id!r}, got {sorted(listed_ids)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
