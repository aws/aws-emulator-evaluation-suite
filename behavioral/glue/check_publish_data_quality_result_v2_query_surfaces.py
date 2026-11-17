"""publish-data-quality-result-v2-query-surfaces."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "publish-data-quality-result-v2-query-surfaces"
GROUP = "data-quality"
SERVICES = ["glue"]


def _rule_results(name: str, result: str) -> list[dict]:
    return [{"Name": name, "Result": result}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A result PublishDataQualityResultV2 creates is readable by its own id through
    GetDataQualityResultV2 and BatchGetDataQualityResultV2, and is found or excluded by
    ListDataQualityResultsV2 filters on EvaluationContext and on Dimensions.
    """
    glue = ctx.client("glue")
    context_name = ctx.unique_name("sim2real-behav-dqv2-ctx-")
    app_a = ctx.unique_name("sim2real-behav-dqv2-app-a-")
    app_b = ctx.unique_name("sim2real-behav-dqv2-app-b-")

    published_a = glue.publish_data_quality_result_v2(
        Dimensions={"Application": app_a},
        EvaluationContext=context_name,
        Score=0.75,
        RuleResults=_rule_results("row_count_check", "PASS"),
        Descriptors={"Origin": "sim2real"},
    )
    result_id_a = published_a["ResultId"]

    published_b = glue.publish_data_quality_result_v2(
        Dimensions={"Application": app_b},
        EvaluationContext=context_name,
        Score=0.5,
        RuleResults=_rule_results("row_count_check", "FAIL"),
    )
    result_id_b = published_b["ResultId"]

    # GetDataQualityResultV2 returns exactly what was published, by id
    fetched_a = glue.get_data_quality_result_v2(ResultId=result_id_a)
    assert fetched_a["Score"] == 0.75, f"score mismatch: {fetched_a['Score']!r} != 0.75"
    assert fetched_a["Dimensions"] == {"Application": app_a}, (
        f"dimensions mismatch: {fetched_a['Dimensions']!r}"
    )
    assert fetched_a["EvaluationContext"] == context_name, (
        f"evaluation context mismatch: {fetched_a['EvaluationContext']!r} != {context_name!r}"
    )
    assert fetched_a["RuleResults"] == _rule_results("row_count_check", "PASS"), (
        f"rule results mismatch: {fetched_a['RuleResults']!r}"
    )
    assert fetched_a["Descriptors"] == {"Origin": "sim2real"}, (
        f"descriptors mismatch: {fetched_a['Descriptors']!r}"
    )

    # BatchGetDataQualityResultV2 separates known ids from an id that was never published;
    # the id is shaped like a real one (real ids are "dqresult-" + 40 hex characters)
    fabricated_id = "dqresult-" + secrets.token_hex(20)
    batch = glue.batch_get_data_quality_result_v2(
        ResultIds=[result_id_a, result_id_b, fabricated_id]
    )
    found_ids = {r["ResultId"] for r in batch["Results"]}
    assert found_ids == {result_id_a, result_id_b}, (
        f"BatchGetDataQualityResultV2 found {found_ids!r}, expected {{result_id_a, result_id_b}}"
    )
    assert batch["ResultsNotFound"] == [fabricated_id], (
        f"BatchGetDataQualityResultV2.ResultsNotFound was {batch['ResultsNotFound']!r}, "
        f"expected [{fabricated_id!r}]"
    )

    # ListDataQualityResultsV2 filtered by EvaluationContext finds both; filtered by one
    # Application's Dimensions it finds only that one
    by_context_ids = set()
    paginator = glue.get_paginator("list_data_quality_results_v2")
    for page in paginator.paginate(Filter={"EvaluationContext": context_name}):
        by_context_ids.update(r["ResultId"] for r in page["Results"])
    assert {result_id_a, result_id_b} <= by_context_ids, (
        f"ListDataQualityResultsV2(EvaluationContext={context_name!r}) missing published results, "
        f"got {by_context_ids!r}"
    )

    by_dimension_ids = set()
    for page in glue.get_paginator("list_data_quality_results_v2").paginate(
        Filter={"Dimensions": {"Application": app_a}}
    ):
        by_dimension_ids.update(r["ResultId"] for r in page["Results"])
    assert result_id_a in by_dimension_ids, (
        f"ListDataQualityResultsV2(Dimensions.Application={app_a!r}) missing {result_id_a!r}"
    )
    assert result_id_b not in by_dimension_ids, (
        f"ListDataQualityResultsV2(Dimensions.Application={app_a!r}) wrongly returned the other "
        f"application's result {result_id_b!r}"
    )

    # the v1 BatchGetDataQualityResult surface shares the same result store: it also serves
    # a result that was only ever published through PublishDataQualityResultV2
    v1_batch = glue.batch_get_data_quality_result(ResultIds=[result_id_a, result_id_b])
    v1_by_id = {r["ResultId"]: r for r in v1_batch["Results"]}
    assert set(v1_by_id) == {result_id_a, result_id_b}, (
        f"BatchGetDataQualityResult (v1) found {sorted(v1_by_id)!r}, expected both v2-published ids"
    )
    assert v1_by_id[result_id_a]["Score"] == 0.75, (
        f"v1 score for a v2-published result was {v1_by_id[result_id_a]['Score']!r}, expected 0.75"
    )
    assert v1_by_id[result_id_a]["RuleResults"] == _rule_results("row_count_check", "PASS"), (
        f"v1 rule results for a v2-published result were {v1_by_id[result_id_a]['RuleResults']!r}"
    )
    assert "ResultsNotFound" not in v1_batch, (
        f"BatchGetDataQualityResult (v1) unexpectedly set ResultsNotFound: {v1_batch['ResultsNotFound']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
