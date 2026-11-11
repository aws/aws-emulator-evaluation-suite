"""glue-job-authored-catalog-table-is-read-by-athena-and-a-partition-denied-role-fails."""
from __future__ import annotations

import json
import sys
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-job-authored-catalog-table-is-read-by-athena-and-a-partition-denied-role-fails"
GROUP = 'jobs'
SERVICES = ['athena', 'glue', 's3']

# Two Glue 4.0 G.1X x2 runs (48-77 s each, startup to terminal) plus four short Athena queries.
# One hard cap shared by every wait below.
_TOTAL_DEADLINE_S = 1200.0

_DTS = ("2026-01-01", "2026-01-02", "2026-01-03")
_ROWS = 300

_SERDE = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
_INPUT_FORMAT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
_OUTPUT_FORMAT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

# AWSGlueServiceRole already grants glue:*, so omitting partition actions from an inline
# policy changes nothing. Only an explicit Deny breaks it, and the denial that surfaces names
# glue:BatchCreatePartition.
_DENIED_ACTIONS = ["glue:CreatePartition", "glue:BatchCreatePartition"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _build_input() -> tuple[bytes, dict]:
    """The input CSV, plus the per-dt aggregates it implies. Pure arithmetic."""
    lines = []
    agg: dict[str, list] = {d: [0, 0.0] for d in _DTS}
    for i in range(1, _ROWS + 1):
        dt = _DTS[i % 3]
        amount = round((i % 41) + 0.5, 2)
        lines.append(f"{i},{amount},{dt}")
        agg[dt][0] += 1
        agg[dt][1] += amount
    csv = ("order_id,amount,dt\n" + "\n".join(lines) + "\n").encode()
    return csv, {d: (n, round(total, 6)) for d, (n, total) in agg.items()}


_CSV, _EXPECTED = _build_input()

# A real Glue job whose SINK writes the Data Catalog entry. enableUpdateCatalog makes the job
# process call back into the Glue Catalog API with a schema it inferred itself and one
# partition per value it wrote. The check never creates the table.
_SCRIPT = b"""import sys
from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext

a = getResolvedOptions(sys.argv, ['JOB_NAME', 'INPUT', 'OUTPUT', 'DB', 'TBL'])
sc = SparkContext.getOrCreate()
gc = GlueContext(sc)
job = Job(gc)
job.init(a['JOB_NAME'], a)
df = gc.spark_session.read.option('header', 'true').csv(a['INPUT'])
df = df.selectExpr("cast(order_id as int) order_id", "cast(amount as double) amount", "dt")
sink = gc.getSink(path=a['OUTPUT'], connection_type='s3',
                  updateBehavior='UPDATE_IN_DATABASE', partitionKeys=['dt'],
                  compression='snappy', enableUpdateCatalog=True,
                  transformation_ctx='sink')
sink.setCatalogInfo(catalogDatabase=a['DB'], catalogTableName=a['TBL'])
sink.setFormat('glueparquet')
sink.writeFrame(DynamicFrame.fromDF(df, gc, 'dyf'))
job.commit()
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue Spark job authors its own Catalog table and partitions, and Athena reads the expected
    per-dt counts and sums; a role with an explicit Deny on BatchCreatePartition fails inside
    pyWriteDynamicFrame yet leaves a table and Parquet objects with zero partitions."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    athena = ctx.client("athena")

    budget = time.monotonic() + _budget_s(ctx, _TOTAL_DEADLINE_S)

    bucket = ctx.unique_name("sim2real-behav-b5cat-").lower()
    database = ctx.unique_name("sim2real_behav_b5cat_").replace("-", "_").lower()
    table_ok = f"{database}_ok"
    table_denied = f"{database}_denied"
    role_ok = ctx.unique_name("sim2real-behav-b5catrole-")
    role_denied = ctx.unique_name("sim2real-behav-b5denyrole-")
    job_ok = ctx.unique_name("sim2real-behav-b5cat-")
    job_denied = ctx.unique_name("sim2real-behav-b5catdeny-")

    try:
        _create_bucket(ctx, s3, bucket)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
        s3.put_bucket_tagging(Bucket=bucket,
                              Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
        s3.put_object(Bucket=bucket, Key="scripts/cat.py", Body=_SCRIPT)
        s3.put_object(Bucket=bucket, Key="input/sales.csv", Body=_CSV)

        glue.create_database(DatabaseInput={"Name": database})
        ctx.on_cleanup(lambda: _retry_delete(
            lambda: glue.delete_database(Name=database), f"glue database {database}"))
        # The JOB creates these tables, so cleanup is registered before the run that creates
        # them -- a table that appears and then fails an assertion must still be deleted.
        for tbl in (table_denied, table_ok):
            ctx.on_cleanup(lambda t=tbl: _retry_delete(
                lambda: glue.delete_table(DatabaseName=database, Name=t),
                f"glue table {database}.{t}"))

        arn_ok = _create_glue_role(ctx, iam, role_ok, bucket, deny=None)
        arn_denied = _create_glue_role(ctx, iam, role_denied, bucket, deny=_DENIED_ACTIONS)
        # IAM propagation exposes no condition to poll: _run_job_to_terminal's bounded retry on
        # the "assume role permissions" run failure is the only wait.

        command = {"Name": "glueetl", "PythonVersion": "3",
                   "ScriptLocation": f"s3://{bucket}/scripts/cat.py"}
        default_args = {"--TempDir": f"s3://{bucket}/tmp/"}
        for name, role_arn in ((job_ok, arn_ok), (job_denied, arn_denied)):
            glue.create_job(Name=name, Role=role_arn, Command=dict(command),
                            GlueVersion="4.0", WorkerType="G.1X", NumberOfWorkers=2,
                            MaxRetries=0, ExecutionProperty={"MaxConcurrentRuns": 5},
                            DefaultArguments=dict(default_args),
                            Tags={"sim2real": CHECK})
            ctx.on_cleanup(lambda n=name: _retry_delete(
                lambda: glue.delete_job(JobName=n), f"glue job {n}"))

        # ------------------------------------------------- the control run: job writes catalog
        good = _run_job_to_terminal(glue, job_ok, {
            "--INPUT": f"s3://{bucket}/input/sales.csv",
            "--OUTPUT": f"s3://{bucket}/cout/", "--DB": database,
            "--TBL": table_ok}, budget=budget, ctx=ctx)
        assert good["JobRunState"] == "SUCCEEDED", (
            f"the catalog-writing run ended {good['JobRunState']!r}: "
            f"{good.get('ErrorMessage')!r}"
        )
        assert good["ExecutionTime"] > 0, (
            f"ExecutionTime was {good['ExecutionTime']!r} on a SUCCEEDED run, so no Spark "
            f"compute was billed and nothing actually executed"
        )

        table = glue.get_table(DatabaseName=database, Name=table_ok)["Table"]
        descriptor = table["StorageDescriptor"]

        params = table.get("Parameters") or {}
        assert params.get("CreatedByJob") == job_ok, (
            f"the table's CreatedByJob parameter is {params.get('CreatedByJob')!r}, expected "
            f"{job_ok!r}; the catalog records which job authored the entry, and the check "
            f"never created this table"
        )
        assert params.get("CreatedByJobRun") == good["Id"], (
            f"the table's CreatedByJobRun is {params.get('CreatedByJobRun')!r}, expected the "
            f"run id {good['Id']!r}"
        )
        assert params.get("classification") == "parquet", (
            f"the sink registered classification {params.get('classification')!r}, expected "
            f"'parquet'"
        )
        assert params.get("useGlueParquetWriter") == "true", (
            f"useGlueParquetWriter was {params.get('useGlueParquetWriter')!r}; "
            f"setFormat('glueparquet') must be recorded on the table it created"
        )
        assert table.get("TableType") == "EXTERNAL_TABLE", (
            f"the job-authored table's TableType is {table.get('TableType')!r}"
        )

        assert table.get("PartitionKeys") == [{"Name": "dt", "Type": "string"}], (
            f"PartitionKeys are {table.get('PartitionKeys')!r}, expected "
            f"[{{'Name': 'dt', 'Type': 'string'}}]; the sink must register the partition key, "
            f"not only the columns"
        )
        assert descriptor.get("Columns") == [{"Name": "order_id", "Type": "int"},
                                            {"Name": "amount", "Type": "double"}], (
            f"the sink inferred columns {descriptor.get('Columns')!r}; expected order_id:int "
            f"and amount:double in order, with 'dt' NOT among them because it is a partition "
            f"key"
        )
        assert descriptor["SerdeInfo"]["SerializationLibrary"] == _SERDE, (
            f"SerializationLibrary is "
            f"{descriptor['SerdeInfo']['SerializationLibrary']!r}, expected {_SERDE!r}"
        )
        assert descriptor.get("InputFormat") == _INPUT_FORMAT, (
            f"InputFormat is {descriptor.get('InputFormat')!r}, expected {_INPUT_FORMAT!r}"
        )
        assert descriptor.get("OutputFormat") == _OUTPUT_FORMAT, (
            f"OutputFormat is {descriptor.get('OutputFormat')!r}, expected {_OUTPUT_FORMAT!r}"
        )
        assert descriptor.get("Location") == f"s3://{bucket}/cout/", (
            f"the table Location is {descriptor.get('Location')!r}, expected the job's own "
            f"output prefix s3://{bucket}/cout/"
        )

        partitions = _all_partitions(glue, database, table_ok)
        values = sorted(tuple(p["Values"]) for p in partitions)
        assert values == [(d,) for d in _DTS], (
            f"the job created partitions {values!r}, expected exactly one per written dt "
            f"value {[(d,) for d in _DTS]!r}"
        )
        locations = sorted(p["StorageDescriptor"]["Location"] for p in partitions)
        expected_locations = sorted(f"s3://{bucket}/cout/dt={d}" for d in _DTS)
        assert locations == expected_locations, (
            f"partition locations are {locations!r}, expected {expected_locations!r}"
        )

        # ------------------------------------------------------------- Athena reads it back
        grouped = _athena(athena, database, bucket,
                          f'SELECT dt, count(*) c, sum(amount) s FROM "{database}"."'
                          f'{table_ok}" GROUP BY dt ORDER BY dt', budget=budget, ctx=ctx)
        assert grouped["state"] == "SUCCEEDED", (
            f"the GROUP BY query over the job-authored table ended {grouped['state']!r}: "
            f"{grouped['reason']!r}"
        )
        got = {row[0]: (int(row[1]), round(float(row[2]), 6)) for row in grouped["rows"]}
        assert got == _EXPECTED, (
            f"Athena returned per-dt (count, sum(amount)) {got!r}, expected {_EXPECTED!r} -- "
            f"numbers derivable only from the 300 rows the check uploaded, read through a "
            f"SerDe the job registered, over Parquet the job wrote"
        )

        pruned = _athena(athena, database, bucket,
                         f'SELECT count(*) FROM "{database}"."{table_ok}" '
                         f"WHERE dt = '{_DTS[1]}'", budget=budget, ctx=ctx)
        assert pruned["state"] == "SUCCEEDED", (
            f"the partition-pruned query ended {pruned['state']!r}: {pruned['reason']!r}"
        )
        assert int(pruned["rows"][0][0]) == _EXPECTED[_DTS[1]][0], (
            f"the pruned query returned {pruned['rows']!r}, expected "
            f"{_EXPECTED[_DTS[1]][0]} rows for dt={_DTS[1]!r}"
        )

        total = _athena(athena, database, bucket,
                        f'SELECT count(*) FROM "{database}"."{table_ok}"', budget=budget, ctx=ctx)
        assert int(total["rows"][0][0]) == _ROWS, (
            f"an unfiltered count over the job-authored table returned {total['rows']!r}, "
            f"expected {_ROWS}; the pruned query must be a strict subset of a whole table "
            f"that really holds every row"
        )

        # -------------------------- negative arm: one explicit Deny, everything else identical
        denied = _run_job_to_terminal(glue, job_denied, {
            "--INPUT": f"s3://{bucket}/input/sales.csv",
            "--OUTPUT": f"s3://{bucket}/coutd/", "--DB": database,
            "--TBL": table_denied}, budget=budget, ctx=ctx)
        assert denied["JobRunState"] == "FAILED", (
            f"the run whose execution role explicitly denies "
            f"CreatePartition/BatchCreatePartition ended {denied['JobRunState']!r}, expected "
            f"FAILED; ErrorMessage was {denied.get('ErrorMessage')!r}"
        )
        message = denied.get("ErrorMessage") or ""
        assert "AccessDeniedException" in message, (
            f"the denied run's ErrorMessage does not report an AccessDeniedException: "
            f"{message!r}"
        )
        assert "glue:BatchCreatePartition" in message, (
            f"the denied run's ErrorMessage does not name the denied action "
            f"glue:BatchCreatePartition: {message!r}"
        )
        assert "pyWriteDynamicFrame" in message, (
            f"the denial must surface from the sink's write inside the job process, so the "
            f"ErrorMessage must name pyWriteDynamicFrame; it was {message!r}"
        )
        assert denied["ExecutionTime"] > 0, (
            f"the denied run's ExecutionTime was {denied['ExecutionTime']!r}; the execution "
            f"role must be evaluated at write time by real compute, not pre-flighted at "
            f"StartJobRun"
        )

        # the two failure surfaces are distinguished: table yes, partitions no, Parquet yes
        denied_table = glue.get_table(DatabaseName=database, Name=table_denied)["Table"]
        assert (denied_table["StorageDescriptor"]["SerdeInfo"]["SerializationLibrary"]
                == _SERDE), (
            f"the denied run's table exists but with SerDe "
            f"{denied_table['StorageDescriptor']['SerdeInfo']!r}"
        )
        denied_partitions = _all_partitions(glue, database, table_denied)
        assert denied_partitions == [], (
            f"the denied run registered partitions anyway: "
            f"{[p['Values'] for p in denied_partitions]!r}"
        )
        denied_dirs = sorted({k.split("/")[1] for k in _list_keys(s3, bucket, "coutd/")})
        assert denied_dirs == sorted(f"dt={d}" for d in _DTS), (
            f"the denied run wrote Parquet directories {denied_dirs!r}, expected all three "
            f"{sorted(f'dt={d}' for d in _DTS)!r} -- the S3 write succeeded and only the "
            f"catalog update was refused, which is what makes this failure silent"
        )

        denied_query = _athena(athena, database, bucket,
                               f'SELECT count(*) FROM "{database}"."{table_denied}"',
                               budget=budget, ctx=ctx)
        assert denied_query["state"] == "SUCCEEDED", (
            f"querying the partition-less table ended {denied_query['state']!r}: "
            f"{denied_query['reason']!r}; it must succeed and return nothing, which is the "
            f"dangerous outcome"
        )
        assert int(denied_query["rows"][0][0]) == 0, (
            f"Athena returned {denied_query['rows']!r} over a table with zero partitions, "
            f"expected 0 rows even though {len(denied_dirs)} partition directories of Parquet "
            f"exist in S3"
        )

        control = _athena(athena, database, bucket,
                          f'SELECT count(*) FROM "{database}"."{table_ok}"', budget=budget, ctx=ctx)
        assert int(control["rows"][0][0]) == _ROWS, (
            f"the control table stopped returning its {_ROWS} rows after the denied run: "
            f"{control['rows']!r}"
        )

        assert (glue.get_job(JobName=job_ok)["Job"]["Command"]
                == glue.get_job(JobName=job_denied)["Job"]["Command"]), (
            f"the two jobs must differ only in their execution role; Commands were "
            f"{glue.get_job(JobName=job_ok)['Job']['Command']!r} and "
            f"{glue.get_job(JobName=job_denied)['Job']['Command']!r}"
        )
        assert (glue.get_job(JobName=job_ok)["Job"]["DefaultArguments"]
                == glue.get_job(JobName=job_denied)["Job"]["DefaultArguments"]), (
            "the two jobs' DefaultArguments must be identical for the comparison to be "
            "controlled"
        )
        document = iam.get_role_policy(RoleName=role_denied,
                                       PolicyName="sim2real")["PolicyDocument"]
        if isinstance(document, str):
            document = json.loads(document)
        denies = [st for st in document["Statement"] if st["Effect"] == "Deny"]
        assert len(denies) == 1 and sorted(denies[0]["Action"]) == sorted(_DENIED_ACTIONS), (
            f"the denied role's policy is not what this check claims it is: {denies!r}"
        )

    finally:
        # Verified inline teardown: ctx.on_cleanup failures never affect the verdict, so a
        # leak there would go unreported.
        _teardown(glue, s3, iam, athena,
                  jobs=[job_ok, job_denied],
                  tables=[(database, table_ok), (database, table_denied)],
                  database=database, bucket=bucket,
                  roles=[role_ok, role_denied])



def _all_partitions(glue, database: str, table: str) -> list:
    out = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                              TableName=table):
        out.extend(page["Partitions"])
    return out


def _athena(athena, database: str, bucket: str, sql: str, *, budget: float, ctx=None) -> dict:
    """Run one Athena query to a terminal state and return its state plus its data rows."""
    query_id = athena.start_query_execution(
        QueryString=sql, QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/athena/"}
    )["QueryExecutionId"]
    deadline = min(time.monotonic() + 300.0, budget)
    execution: dict = {}
    while time.monotonic() < deadline:
        execution = athena.get_query_execution(
            QueryExecutionId=query_id)["QueryExecution"]
        if execution["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2)
    state = execution.get("Status", {}).get("State")
    if (state not in ("SUCCEEDED", "FAILED", "CANCELLED") and ctx is not None
            and _budget_spent(ctx)):
        raise TimeoutError(f"Athena query {sql!r} reaching a terminal state: the run budget ended "
                           "first; not graded")
    assert state in ("SUCCEEDED", "FAILED", "CANCELLED"), (
        f"Athena query {sql!r} never reached a terminal state; last was {state!r}"
    )
    out = {"state": state,
           "reason": execution["Status"].get("StateChangeReason"),
           "rows": []}
    if state == "SUCCEEDED":
        rows = []
        paginator = athena.get_paginator("get_query_results")
        for page in paginator.paginate(QueryExecutionId=query_id):
            rows.extend(page["ResultSet"]["Rows"])
        # Athena's first row is the column-name header, never data.
        out["rows"] = [[c.get("VarCharValue") for c in r["Data"]] for r in rows[1:]]
    return out


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, role: str, bucket: str, *, deny) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    statements = [
        {"Effect": "Allow",
         "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
         "Resource": f"arn:aws:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": f"arn:aws:s3:::{bucket}"}]
    if deny:
        statements.append({"Effect": "Deny", "Action": list(deny), "Resource": "*"})
    iam.put_role_policy(RoleName=role, PolicyName="sim2real",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real"),
        f"inline policy on {role}"))
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, budget: float, ctx=None) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure, which
    Glue reports as a FAILED run ("should be given assume role permissions"), not a StartJobRun
    error. ``budget`` is the check's shared monotonic deadline."""
    from botocore.exceptions import ClientError

    record: dict = {}
    while time.monotonic() < budget:
        try:
            run_id = glue.start_job_run(JobName=job, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(2)
            continue
        while time.monotonic() < budget:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(2)
        else:
            break
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"job {job!r} reaching a terminal run state: the run budget ended "
                           "first; not graded")
    raise AssertionError(
        f"job {job!r} did not reach a terminal run state inside the check's "
        f"budget; last record was {record!r}")


def _teardown(glue, s3, iam, athena, *, jobs, tables, database, bucket, roles) -> None:
    """Delete everything, children before parents, polling each API until the resource is gone.
    Raises naming every resource that could not be verified deleted, and the in-flight error."""
    from botocore.exceptions import ClientError
    # One deadline for every delete below, inside the suite's 900 s cleanup budget.
    deadline = time.monotonic() + 600.0

    def verify(label: str, delete: Callable[[], Any], probe: Callable[[], Any],
               gone_codes: tuple) -> None:
        while True:
            try:
                delete()
                break
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code in gone_codes:
                    break
                if code not in ("DeleteConflict", "BucketNotEmpty") or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        while True:
            try:
                probe()
            except ClientError as err:
                if err.response["Error"]["Code"] in gone_codes:
                    return
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{label}: still present at the teardown deadline")
            time.sleep(2)

    def detach(role: str) -> None:
        for policy in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=policy)
        for attached in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role, PolicyArn=attached["PolicyArn"])

    def empty() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})

    steps: list = []
    for name in jobs:
        steps.append((f"glue job {name}", lambda n=name: verify(
            f"glue job {n}", lambda: glue.delete_job(JobName=n),
            lambda: glue.get_job(JobName=n), ("EntityNotFoundException",))))
    for db, tbl in tables:
        steps.append((f"glue table {db}.{tbl}", lambda d=db, t=tbl: verify(
            f"glue table {d}.{t}", lambda: glue.delete_table(DatabaseName=d, Name=t),
            lambda: glue.get_table(DatabaseName=d, Name=t), ("EntityNotFoundException",))))
    steps.append((f"glue database {database}", lambda: verify(
        f"glue database {database}", lambda: glue.delete_database(Name=database),
        lambda: glue.get_database(Name=database), ("EntityNotFoundException",))))
    for role in roles:
        steps.append((f"iam role {role}: detaching policies", lambda r=role: detach(r)))
        steps.append((f"iam role {role}", lambda r=role: verify(
            f"iam role {r}", lambda: iam.delete_role(RoleName=r),
            lambda: iam.get_role(RoleName=r), ("NoSuchEntity",))))
    # Each BucketNotEmpty retry empties again: late writes (Athena results) land after a first pass.
    steps.append((f"s3 bucket {bucket}", lambda: verify(
        f"s3 bucket {bucket}", lambda: (empty(), s3.delete_bucket(Bucket=bucket)),
        lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket"))))
    leaks: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected, then raised below
            leaks.append(f"{label}: {exc!r}")
    if leaks:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"the inline teardown could not verify every resource was gone: {leaks!r}"
        )


def _list_keys(s3, bucket: str, prefix: str) -> list:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "InvalidInputException", "RequestLimitExceeded",
                 "ConcurrentRunsExceededException")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """The ctx.on_cleanup failure-path net. The inline teardown in run()'s `finally` normally
    got here first, so an already-absent bucket is the expected case, not a leak."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 600.0
    while True:
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objects:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
