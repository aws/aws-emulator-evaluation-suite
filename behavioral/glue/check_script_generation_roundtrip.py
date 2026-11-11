"""script-generation-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "script-generation-roundtrip"
GROUP = 'script'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """get_mapping -> get_plan -> get_dataflow_graph -> create_script is a closed round trip."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    src = ctx.unique_name("sim2real-behav-tbl-src-")
    dst = ctx.unique_name("sim2real-behav-tbl-dst-")

    columns = [{"Name": "id", "Type": "string"}, {"Name": "amount", "Type": "double"}]
    for tn in (src, dst):
        glue.create_table(
            DatabaseName=db_name,
            TableInput={
                "Name": tn,
                # GetPlan refuses tables without a classification: the ETL code
                # generator needs to know the format to emit a reader/writer for.
                "Parameters": {"classification": "csv"},
                "StorageDescriptor": {
                    "Columns": columns,
                    "Location": f"s3://example-bucket/{tn}/",
                    "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                    "OutputFormat": (
                        "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
                    ),
                    "SerdeInfo": {
                        "SerializationLibrary": (
                            "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                        ),
                        "Parameters": {"field.delim": ","},
                    },
                },
            },
        )
        ctx.on_cleanup(lambda tn=tn: glue.delete_table(DatabaseName=db_name, Name=tn))

    source = {"DatabaseName": db_name, "TableName": src}
    sinks = [{"DatabaseName": db_name, "TableName": dst}]

    mapping = glue.get_mapping(Source=source, Sinks=sinks)["Mapping"]
    assert mapping, "GetMapping must propose a non-empty column mapping"
    mapped_sources = {m["SourcePath"] for m in mapping}
    assert {"id", "amount"} <= mapped_sources, (
        f"GetMapping must cover every source column, got {mapped_sources}"
    )

    script = glue.get_plan(Mapping=mapping, Source=source, Sinks=sinks, Language="PYTHON")["PythonScript"]
    assert "glueContext" in script, f"GetPlan must emit a Glue ETL script, got: {script[:200]!r}"
    assert src in script and dst in script, (
        f"GetPlan's script must reference the real source/sink tables {src!r}/{dst!r}, "
        f"got: {script[:400]!r}"
    )

    graph = glue.get_dataflow_graph(PythonScript=script)
    assert graph["DagNodes"], "GetDataflowGraph must parse the generated script into DAG nodes"
    node_types = {n["NodeType"] for n in graph["DagNodes"]}
    assert "DataSource" in node_types and "DataSink" in node_types, (
        f"GetDataflowGraph must parse the script into a source and a sink node, got node types: {node_types}"
    )

    regenerated = glue.create_script(
        DagNodes=graph["DagNodes"], DagEdges=graph["DagEdges"], Language="PYTHON"
    )["PythonScript"]
    assert "glueContext" in regenerated, (
        f"CreateScript must regenerate a Glue ETL script, got: {regenerated[:200]!r}"
    )
    assert src in regenerated and dst in regenerated, (
        f"CreateScript's regenerated script must still reference the real source/sink tables "
        f"{src!r}/{dst!r}, got: {regenerated[:400]!r}"
    )

    # Close the round trip for real: the regenerated script must itself parse back into a
    # dataflow graph with the same node shape as the one that produced it, otherwise
    # CreateScript(DagNodes, DagEdges) and GetDataflowGraph(PythonScript) disagree about
    # the DAG they claim to share.
    graph2 = glue.get_dataflow_graph(PythonScript=regenerated)
    assert len(graph2["DagNodes"]) == len(graph["DagNodes"]), (
        f"round trip must close: re-parsing the regenerated script produced "
        f"{len(graph2['DagNodes'])} DAG nodes, expected {len(graph['DagNodes'])} "
        f"(the graph CreateScript was given)"
    )
    assert {n["NodeType"] for n in graph2["DagNodes"]} == node_types, (
        f"round trip must close: re-parsing the regenerated script produced node types "
        f"{ {n['NodeType'] for n in graph2['DagNodes']} }, expected {node_types}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
