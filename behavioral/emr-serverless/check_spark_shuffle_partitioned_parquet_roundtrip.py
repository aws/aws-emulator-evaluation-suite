"""spark-shuffle-partitioned-parquet-roundtrip."""
from __future__ import annotations

import json
import random
import struct
import time
import uuid

from behavioral_harness import tags

CHECK = "spark-shuffle-partitioned-parquet-roundtrip"
GROUP = "data-plane"
SERVICES = ["emr-serverless"]

RELEASE_LABEL = "emr-7.9.0"

# Declared deadlines: a cold Spark job run on emr-7.9.0 takes 2-5 min to leave PENDING, so the job
# budget is well over 300 s.
_JOB_BUDGET_S = 1200.0
_APP_TEARDOWN_BUDGET_S = 420.0

_DATES = ("2026-01-01", "2026-01-02", "2026-01-03", "2026-01-04", "2026-01-05")
_REGIONS = ("eu-west", "eu-east", "us-west", "us-east", "ap-south", "sa-east")
_ROWS_PER_DATE = 400
_TOTAL_ROWS = _ROWS_PER_DATE * len(_DATES)
_SHUFFLE_PARTITIONS = 8

# Parquet physical types (parquet.thrift `Type`).
_PQ_INT32, _PQ_INT64, _PQ_DOUBLE, _PQ_BYTE_ARRAY = 1, 2, 5, 6

# The job. Two independent datasets are joined on `region` with the broadcast threshold DISABLED, so
# Spark cannot collapse the join into a map-side broadcast and must run a real hash exchange; the
# groupBy is a second exchange. The output is written partitionBy("dt"), and the job ALSO writes its
# own aggregate as one JSON line so the runner can compare Spark's answer against a value it computed
# in Python from the same seeded input. Nothing here is closed-form: the amounts are drawn from a
# per-run seed, so no recording can supply the right answer.
_SPARK_JOB = '''\
import json
import sys

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, sum as _sum

facts_uri, dim_uri, out_uri, answer_uri = sys.argv[1:5]

spark = SparkSession.builder.appName("sim2real-emrs-shuffle").getOrCreate()

facts = spark.read.option("header", True).option("inferSchema", True).csv(facts_uri)
dim = spark.read.option("header", True).option("inferSchema", True).csv(dim_uri)

joined = facts.join(dim, on="region")
agg = joined.groupBy("dt", "region").agg(
    _sum(col("amount").cast("double") * col("multiplier").cast("double")).alias("weighted"),
    count("*").alias("n"),
)
agg.cache()
agg.write.mode("overwrite").partitionBy("dt").parquet(out_uri)

rows = sorted(
    [str(r["dt"]), str(r["region"]), float(r["weighted"]), int(r["n"])] for r in agg.collect()
)
spark.createDataFrame([(json.dumps(rows),)], ["payload"]).coalesce(1) \\
    .write.mode("overwrite").text(answer_uri)
spark.stop()
'''


# ===== stdlib Parquet footer reader =====
# A Parquet footer is a Thrift compact-protocol struct; decoding it with stdlib `struct` yields the
# schema, row count, row groups and column statistics of the bytes AWS produced, with no dependency.
class _TCompact:
    """Minimal Thrift compact-protocol reader (structs, lists, maps, scalars)."""

    def __init__(self, buf: bytes) -> None:
        self.b = buf
        self.i = 0

    def _byte(self) -> int:
        v = self.b[self.i]
        self.i += 1
        return v

    def _varint(self) -> int:
        result = 0
        shift = 0
        while True:
            c = self._byte()
            result |= (c & 0x7F) << shift
            if not c & 0x80:
                return result
            shift += 7

    def _zigzag(self) -> int:
        n = self._varint()
        return (n >> 1) ^ -(n & 1)

    def _binary(self) -> bytes:
        n = self._varint()
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def _value(self, t: int):
        if t == 1:
            return True
        if t == 2:
            return False
        if t == 3:
            return self._byte()
        if t in (4, 5, 6):
            return self._zigzag()
        if t == 7:
            v = struct.unpack_from("<d", self.b, self.i)[0]
            self.i += 8
            return v
        if t == 8:
            return self._binary()
        if t in (9, 10):
            return self._collection()
        if t == 11:
            return self._map()
        if t == 12:
            return self.struct()
        raise AssertionError(f"unknown thrift compact type {t} at offset {self.i}")

    def _collection(self) -> list:
        h = self._byte()
        size, et = h >> 4, h & 0x0F
        if size == 15:
            size = self._varint()
        return [self._value(et) for _ in range(size)]

    def _map(self) -> dict:
        size = self._varint()
        if size == 0:
            return {}
        h = self._byte()
        kt, vt = h >> 4, h & 0x0F
        return {self._value(kt): self._value(vt) for _ in range(size)}

    def struct(self) -> dict:
        out: dict[int, object] = {}
        fid = 0
        while True:
            h = self._byte()
            if h == 0:
                return out
            delta, t = h >> 4, h & 0x0F
            fid = fid + delta if delta else self._zigzag()
            out[fid] = self._value(t)


def _parquet_metadata(body: bytes) -> dict:
    """Decode a Parquet file's FileMetaData footer. Raises AssertionError on a malformed file."""
    assert len(body) > 12, f"object is {len(body)} bytes — too small to be a Parquet file"
    assert body[:4] == b"PAR1", f"missing leading PAR1 magic, got {body[:4]!r}"
    assert body[-4:] == b"PAR1", f"missing trailing PAR1 magic, got {body[-4:]!r}"
    footer_len = struct.unpack("<I", body[-8:-4])[0]
    start = len(body) - 8 - footer_len
    assert 4 <= start, (
        f"declared footer length {footer_len} does not fit in a {len(body)}-byte object"
    )
    return _TCompact(body[start:len(body) - 8]).struct()


def _parquet_leaves(meta: dict) -> list[tuple[str, int, int | None]]:
    """(name, physical_type, converted_type) for each leaf SchemaElement, in schema order."""
    leaves = []
    for el in meta[2]:
        if 1 in el:  # field 1 is `type`, present only on leaves
            leaves.append((el[4].decode("utf-8"), el[1], el.get(6)))
    return leaves


def _parquet_row_groups(meta: dict) -> list[dict]:
    """[{num_rows, columns: {name: {num_values, null_count, codec}}}] per row group."""
    groups = []
    for rg in meta.get(4, []):
        cols = {}
        for chunk in rg.get(1, []):
            md = chunk.get(3) or {}
            path = ".".join(p.decode("utf-8") for p in md.get(3, []))
            stats = md.get(12) or {}
            cols[path] = {
                "num_values": md.get(5),
                "codec": md.get(4),
                "null_count": stats.get(3),
                "min_value": stats.get(6),
                "max_value": stats.get(5),
            }
        groups.append({"num_rows": rg.get(3), "columns": cols})
    return groups


# ===== AWS helpers =====
def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint for it is
    # rejected with InvalidLocationConstraint, so it is the one region this call must omit.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _purge_and_delete() -> None:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_purge_and_delete)


def _create_execution_role(ctx, iam, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-emrs-shuf-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-s3-access", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access")
    )
    # IAM exposes no condition to poll for "this role is now assumable by the service": the retry in
    # _run_job_to_terminal on the specific "Could not assume runtime role" failure is the wait.
    return role_arn


def _start_job_run_with_retry(ctx, emrs, app_id: str, role_arn: str, job_driver: dict) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
                jobDriver=job_driver,
            )["jobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartJobRun never succeeded after IAM propagation wait: {last_exc}")


def _await_job_run(emrs, app_id: str, job_run_id: str, budget_s: float) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]
        if last["state"] in terminal:
            return last
        time.sleep(2)
    raise AssertionError(
        f"job run {job_run_id} never reached a terminal state within {budget_s}s "
        f"(last state {last!r})"
    )


_ROLE_NOT_READY = "Could not assume runtime role"
# A new execution role becomes assumable by EMR Serverless a minute or more after it is created.
_ROLE_READY_TIMEOUT_S = 600.0


def _run_job_to_terminal(ctx, emrs, app_id: str, role_arn: str, job_driver: dict,
                         budget_s: float) -> tuple[str, dict]:
    """Start a job run and wait for a terminal state, retrying ONLY the IAM-propagation failure.

    Measured against real AWS: a freshly created execution role is accepted by StartJobRun (the
    control plane) a minute or more before EMR Serverless can actually assume it, and the symptom is
    a FAILED job run whose stateDetails reads "Could not assume runtime role ...". No API exposes a
    condition to poll for that, so retrying to a deadline IS the wait. Any other failure is
    returned unchanged for the caller to assert on, so this never masks a real refusal.
    """
    left = ctx.time_left()
    deadline = time.monotonic() + (
        _ROLE_READY_TIMEOUT_S if left is None else min(_ROLE_READY_TIMEOUT_S, left)
    )
    while True:
        job_run_id = _start_job_run_with_retry(ctx, emrs, app_id, role_arn, job_driver)
        last = _await_job_run(emrs, app_id, job_run_id, budget_s)
        if not (last["state"] == "FAILED"
                and _ROLE_NOT_READY in (last.get("stateDetails") or "")):
            return job_run_id, last
        if time.monotonic() > deadline:
            raise AssertionError(
                f"execution role {role_arn} never became assumable by emr-serverless within "
                f"{_ROLE_READY_TIMEOUT_S}s: {last!r}"
            )
        time.sleep(2)


def _teardown_application(emrs, app_id: str, budget_s: float) -> None:
    """Stop then delete the application, raising if it does not reach STOPPED within budget_s.

    Runs inline in the check body so a slow stop+delete is bounded by the check's own budget.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    try:
        emrs.stop_application(applicationId=app_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        # An application already stopping, stopped or terminated is refused; the poll settles it.
        if code != "ValidationException":
            raise
    while time.monotonic() < deadline:
        try:
            state = emrs.get_application(applicationId=app_id)["application"]["state"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if state == "TERMINATED":
            return
        if state in ("CREATED", "STOPPED"):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"application {app_id} did not reach STOPPED within {budget_s}s")
    emrs.delete_application(applicationId=app_id)


def _list_keys(s3, bucket: str, prefix: str) -> list[dict]:
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(page.get("Contents", []))
    return out


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real Spark shuffle and partitioned-Parquet write: exactly the five `dt=` partitions, `dt`
    absent from the Parquet schema, a clean commit, and Spark's aggregate equal to the one computed
    here from a per-run seed, so no recorded answer can pass."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-shuffle-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    # --- seeded fixture: the expected answer exists only in this process ---
    seed = uuid.uuid4().int & ((1 << 63) - 1)
    rng = random.Random(seed)
    multipliers = {r: rng.randint(2, 13) for r in _REGIONS}
    expected: dict[tuple[str, str], list[float]] = {}
    for idx, dt in enumerate(_DATES):
        lines = ["id,dt,region,amount"]
        for row in range(_ROWS_PER_DATE):
            region = _REGIONS[rng.randrange(len(_REGIONS))]
            amount = rng.randint(1, 9999)
            lines.append(f"{idx * _ROWS_PER_DATE + row},{dt},{region},{amount}")
            slot = expected.setdefault((dt, region), [0.0, 0])
            slot[0] += float(amount) * float(multipliers[region])
            slot[1] += 1
        s3.put_object(
            Bucket=bucket, Key=f"input/facts/part-{idx:03d}.csv",
            Body=("\n".join(lines) + "\n").encode("utf-8"),
        )
    dim_lines = ["region,multiplier"] + [f"{r},{multipliers[r]}" for r in _REGIONS]
    s3.put_object(
        Bucket=bucket, Key="input/dim/regions.csv",
        Body=("\n".join(dim_lines) + "\n").encode("utf-8"),
    )
    s3.put_object(Bucket=bucket, Key="job/agg.py", Body=_SPARK_JOB.encode("utf-8"))

    role_arn = _create_execution_role(ctx, iam, bucket)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-shuf-app-"),
        releaseLabel=RELEASE_LABEL,
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": CHECK},
    )["applicationId"]
    # Failure-path net only; the verified teardown runs inline in the finally below.
    ctx.on_cleanup(lambda: _teardown_application(emrs, app_id, 120.0))

    try:
        out_uri = f"s3://{bucket}/output/agg/"
        answer_uri = f"s3://{bucket}/output/spark-answer/"
        job_run_id, final = _run_job_to_terminal(ctx, emrs, app_id, role_arn, {
            "sparkSubmit": {
                "entryPoint": f"s3://{bucket}/job/agg.py",
                "entryPointArguments": [
                    f"s3://{bucket}/input/facts/", f"s3://{bucket}/input/dim/",
                    out_uri, answer_uri,
                ],
                "sparkSubmitParameters": (
                    "--conf spark.driver.cores=2 --conf spark.driver.memory=4g "
                    "--conf spark.executor.cores=2 --conf spark.executor.memory=4g "
                    "--conf spark.executor.instances=2 "
                    f"--conf spark.sql.shuffle.partitions={_SHUFFLE_PARTITIONS} "
                    "--conf spark.sql.autoBroadcastJoinThreshold=-1"
                ),
            }
        }, _JOB_BUDGET_S)
        assert final["state"] == "SUCCESS", (
            f"Spark job run {job_run_id} ended {final['state']!r}: "
            f"{final.get('stateDetails')!r}"
        )

        # --- 1. Hive-style partition layout: exactly the five dates, nothing else ---
        out_objects = _list_keys(s3, bucket, "output/agg/")
        assert out_objects, (
            f"job run {job_run_id} reported SUCCESS but wrote nothing under "
            f"s3://{bucket}/output/agg/"
        )
        out_keys = sorted(o["Key"] for o in out_objects)
        partitions = sorted({
            k.split("output/agg/", 1)[1].split("/", 1)[0]
            for k in out_keys if "/" in k.split("output/agg/", 1)[1]
        })
        assert partitions == sorted(f"dt={d}" for d in _DATES), (
            f"partition directories are {partitions!r}, expected exactly "
            f"{sorted('dt=' + d for d in _DATES)!r}"
        )

        # --- 2. the committer wrote _SUCCESS, and wrote it LAST ---
        success = [o for o in out_objects if o["Key"] == "output/agg/_SUCCESS"]
        assert len(success) == 1, (
            f"expected exactly one _SUCCESS at the output root, keys were {out_keys!r}"
        )
        parts = [o for o in out_objects if o["Key"].endswith(".parquet")]
        assert parts, f"no .parquet part files under output/agg/, keys were {out_keys!r}"
        latest_part = max(o["LastModified"] for o in parts)
        assert success[0]["LastModified"] >= latest_part, (
            f"_SUCCESS LastModified {success[0]['LastModified']!r} precedes the newest part file "
            f"{latest_part!r} — the marker was not written last"
        )

        # --- 3. no staging residue ---
        residue = [k for k in out_keys
                   if "_temporary" in k or ".spark-staging" in k or "__magic" in k]
        assert residue == [], f"committer left staging keys behind: {residue!r}"

        # --- 4/5/6/7. Parquet bytes: schema, types, row counts, statistics ---
        per_partition_parts: dict[str, int] = {}
        total_footer_rows = 0
        seen_leaves: set[tuple] = set()
        for obj in parts:
            key = obj["Key"]
            partition = key.split("output/agg/", 1)[1].split("/", 1)[0]
            per_partition_parts[partition] = per_partition_parts.get(partition, 0) + 1
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            meta = _parquet_metadata(body)
            leaves = _parquet_leaves(meta)
            seen_leaves.add(tuple((n, t) for n, t, _ in leaves))
            total_footer_rows += meta[3]
            for group in _parquet_row_groups(meta):
                for name, stats in group["columns"].items():
                    assert stats["null_count"] == 0, (
                        f"{key} row group column {name!r} reports null_count "
                        f"{stats['null_count']!r}; an aggregate output has no nulls"
                    )

        assert len(seen_leaves) == 1, (
            f"part files disagree on their Parquet schema: {sorted(seen_leaves)!r}"
        )
        leaf_schema = next(iter(seen_leaves))
        assert leaf_schema == (
            ("region", _PQ_BYTE_ARRAY), ("weighted", _PQ_DOUBLE), ("n", _PQ_INT64)
        ), (
            f"Parquet leaf schema is {leaf_schema!r}; expected region=BYTE_ARRAY(6), "
            f"weighted=DOUBLE(5), n=INT64(2) — and dt must NOT be a column, partitionBy moves it "
            f"into the path"
        )

        assert total_footer_rows == len(expected), (
            f"Parquet footers report {total_footer_rows} rows in total but the seeded input has "
            f"{len(expected)} distinct (dt,region) groups"
        )
        bad_fanout = {p: c for p, c in per_partition_parts.items()
                      if not 1 <= c <= _SHUFFLE_PARTITIONS}
        assert bad_fanout == {}, (
            f"part-file count per partition outside [1,{_SHUFFLE_PARTITIONS}]: {bad_fanout!r}"
        )

        # --- 8. Spark's own aggregate must equal the Python-computed expectation ---
        answer_objs = [o for o in _list_keys(s3, bucket, "output/spark-answer/")
                       if "/part-" in o["Key"]]
        assert len(answer_objs) == 1, (
            f"expected exactly one spark-answer part object, got "
            f"{sorted(o['Key'] for o in answer_objs)!r}"
        )
        payload = s3.get_object(
            Bucket=bucket, Key=answer_objs[0]["Key"]
        )["Body"].read().decode("utf-8").strip()
        spark_rows = json.loads(payload)
        spark_agg = {(r[0], r[1]): (float(r[2]), int(r[3])) for r in spark_rows}
        assert len(spark_agg) == len(spark_rows), (
            f"Spark returned duplicate (dt,region) groups: {len(spark_rows)} rows, "
            f"{len(spark_agg)} distinct keys"
        )
        py_agg = {k: (v[0], int(v[1])) for k, v in expected.items()}
        assert set(spark_agg) == set(py_agg), (
            f"group set mismatch; only in Spark: {sorted(set(spark_agg) - set(py_agg))!r}; "
            f"only in Python: {sorted(set(py_agg) - set(spark_agg))!r}"
        )
        wrong = {
            k: (spark_agg[k], py_agg[k]) for k in py_agg
            if spark_agg[k][1] != py_agg[k][1]
            or abs(spark_agg[k][0] - py_agg[k][0]) > 1e-6
        }
        assert wrong == {}, (
            f"Spark's shuffled aggregate disagrees with the Python expectation for "
            f"{len(wrong)} group(s) (spark, python): {dict(sorted(wrong.items())[:5])!r}"
        )

        # --- 9. no row dropped OR duplicated by the shuffle ---
        counted = sum(v[1] for v in spark_agg.values())
        assert counted == _TOTAL_ROWS, (
            f"the aggregate accounts for {counted} input rows but {_TOTAL_ROWS} were written — "
            f"the shuffle dropped or duplicated rows"
        )
    finally:
        # Verified inline teardown, under this check's own declared budget.
        _teardown_application(emrs, app_id, _APP_TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
