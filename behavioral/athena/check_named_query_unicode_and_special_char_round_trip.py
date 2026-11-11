"""named-query-unicode-and-special-char-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "named-query-unicode-and-special-char-round-trip"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNamedQuery preserves unicode, emoji, and special characters exactly on GetNamedQuery."""
    athena = ctx.client("athena")
    workgroup = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(Name=workgroup, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
    )

    base = ctx.unique_name("sim2real-nq-")
    fancy_name = f"{base}-t\u00ebst-\u4e2d\u6587-\U0001f389"  # tëst-中文-🎉
    fancy_description = (
        "unicode d\u00e9scription with sp\u00e9cial ch\u00e4rs: "
        "\u00a9\u00ae\u2122 \u65e5\u672c\u8a9e \U0001f680 \"quoted\" & <tag> 'apos' \\backslash\\"
    )
    query_string = (
        "SELECT '\u00e9\u00e8\u00e0 \u4e2d\u6587 \U0001f680 special \"chars\" '' quoted '' end' AS greeting"
    )

    resp = athena.create_named_query(
        Name=fancy_name,
        Description=fancy_description,
        Database="default",
        QueryString=query_string,
        WorkGroup=workgroup,
    )
    named_query_id = resp["NamedQueryId"]

    fetched = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]
    assert fetched["Name"] == fancy_name, f"Name mismatch: {fetched['Name']!r} != {fancy_name!r}"
    assert fetched["Description"] == fancy_description, (
        f"Description mismatch: {fetched['Description']!r} != {fancy_description!r}"
    )
    assert fetched["QueryString"] == query_string, (
        f"QueryString mismatch: {fetched['QueryString']!r} != {query_string!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
