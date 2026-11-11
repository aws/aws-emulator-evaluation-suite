"""batch-array-24-shards-write-own-object-and-out-of-scope-put-denied."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

from behavioral_harness import tags

CHECK = "batch-array-24-shards-write-own-object-and-out-of-scope-put-denied"

GROUP = "container-batch-array-scale"

SERVICES = ["batch", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Each child of a 24-wide Batch array job writes the SHA-256 of its own index's shard, leaving
    exactly 24 correct objects and nothing else, draining in waves under maxvCpus; a job under
    the same jobRole gets AccessDenied on a PUT outside the role's prefix; its in-scope PUT works.
    """
    bat = ctx.client("batch")
    s3 = ctx.client("s3")
    td = _Teardown(ctx)
    ok = False
    try:
        bucket = _create_bucket(ctx, td)

        # 24 shards of check-authored bytes. The index is part of the body, so a child that reads
        # the wrong shard produces the wrong digest and assertion 6 names both sides.
        marker = ctx.unique_name("shard-")
        expected = {}
        for i in range(_ARRAY_SIZE):
            body = (f"{marker}:{i}:" + os.urandom(48).hex() + "\n").encode()
            s3.put_object(Bucket=bucket, Key=f"in/shard-{i}", Body=body)
            expected[i] = hashlib.sha256(body).hexdigest()

        # Scoped to exactly the two prefixes the shard program needs. `other/` is deliberately
        # outside it, and is what the negative arm probes.
        _n, job_role = _iam_role(ctx, td, "jobrole", [
            {"Effect": "Allow", "Action": ["s3:GetObject"],
             "Resource": f"arn:aws:s3:::{bucket}/in/*"},
            {"Effect": "Allow", "Action": ["s3:PutObject"],
             "Resource": f"arn:aws:s3:::{bucket}/out/*"},
        ])
        _e, exec_role = _iam_role(ctx, td, "exec", _EXEC_STATEMENTS)
        log_group = _create_log_group(ctx, td)
        queue = _fargate_stack(ctx, bat, td, max_vcpus=_MAX_VCPUS)

        def _jd(mode):
            return _register_jd(
                ctx, bat, td, ["python3", "-c", _SHARD_PROGRAM],
                exec_role_arn=exec_role, job_role_arn=job_role, image=_AL2023,
                log_group=log_group, vcpu=_VCPU, memory="1024",
                environment=[{"name": "BUCKET", "value": bucket},
                             {"name": "REGION", "value": ctx.region},
                             {"name": "MODE", "value": mode}],
            )

        array_jd = _jd("shard")
        probe_jd = _jd("probe")

        array_id = _submit(ctx, bat, td, queue, array_jd,
                           arrayProperties={"size": _ARRAY_SIZE})
        probe_id = _submit(ctx, bat, td, queue, probe_jd)

        array_job = _poll_until(
            lambda: _describe_job(bat, array_id),
            lambda j: j is not None and (
                j.get("status") in ("SUCCEEDED", "FAILED")
                or ((j.get("arrayProperties") or {}).get("statusSummary") or {}).get("FAILED", 0)
            ),
            timeout_s=_budget_s(ctx, _JOB_TIMEOUT_S),
            ctx=ctx,
            interval_s=2,
            description=f"array job {array_id} terminal",
        )
        summary = (array_job.get("arrayProperties") or {}).get("statusSummary") or {}
        assert summary.get("SUCCEEDED") == _ARRAY_SIZE and summary.get("FAILED", 0) == 0, (
            f"all {_ARRAY_SIZE} array children must SUCCEED; statusSummary={summary!r} "
            f"status={array_job.get('status')!r} statusReason={array_job.get('statusReason')!r}"
        )

        children = _describe_children(bat, array_id)
        assert len(children) == _ARRAY_SIZE, (
            f"ListJobs across every status must enumerate exactly {_ARRAY_SIZE} children, got "
            f"{len(children)}: {sorted(c.get('jobId') for c in children)!r}"
        )
        indexes = sorted((c.get("arrayProperties") or {}).get("index") for c in children)
        assert indexes == list(range(_ARRAY_SIZE)), (
            f"the children's indexes must be exactly 0..{_ARRAY_SIZE - 1} with no gap and no "
            f"duplicate, got {indexes!r}"
        )
        task_arns = {(c.get("container") or {}).get("taskArn") for c in children}
        assert len(task_arns) == _ARRAY_SIZE and None not in task_arns, (
            f"{_ARRAY_SIZE} children must be {_ARRAY_SIZE} distinct ECS tasks -- one execution "
            f"reported N times is the emulator shortcut this rejects; got {len(task_arns)} distinct "
            f"taskArns: {sorted(str(a) for a in task_arns)!r}"
        )
        for c in children:
            idx = (c.get("arrayProperties") or {}).get("index")
            assert (c.get("container") or {}).get("exitCode") == 0, (
                f"child {idx} must exit 0, got container={c.get('container')!r}"
            )
            assert len(c.get("attempts") or []) == 1, (
                f"child {idx} must have run exactly once, got "
                f"{len(c.get('attempts') or [])} attempts"
            )

        # ---- the queue really drained in waves: maxvCpus was a constraint, not advice ----
        started = {(c.get("arrayProperties") or {}).get("index"): c["startedAt"]
                   for c in children if c.get("startedAt")}
        stopped = {(c.get("arrayProperties") or {}).get("index"): c["stoppedAt"]
                   for c in children if c.get("stoppedAt")}
        assert len(started) == _ARRAY_SIZE and len(stopped) == _ARRAY_SIZE, (
            f"every child must report startedAt and stoppedAt; got {len(started)} started and "
            f"{len(stopped)} stopped"
        )
        first_stop = min(stopped.values())
        queued_late = sorted(i for i, t in started.items() if t >= first_stop)
        assert queued_late, (
            f"{_ARRAY_SIZE} children at {_VCPU} vCPU against maxvCpus={_MAX_VCPUS} caps "
            f"concurrency at {int(_MAX_VCPUS / float(_VCPU))}, so at least one child must start "
            f"only once another has finished; every child started before the first finished "
            f"(first stoppedAt={first_stop}, startedAt range "
            f"{min(started.values())}..{max(started.values())})"
        )

        # ---- negative space, then per-shard content ----
        out_keys = sorted(k for k in _keys(s3, bucket) if k.startswith("out/shard-"))
        assert out_keys == sorted(f"out/shard-{i}" for i in range(_ARRAY_SIZE)), (
            f"exactly the {_ARRAY_SIZE} intended output keys must exist and nothing else under "
            f"out/shard-, got {out_keys!r}"
        )
        hosts = set()
        bodies = {}
        for i in range(_ARRAY_SIZE):
            bodies[i] = s3.get_object(Bucket=bucket, Key=f"out/shard-{i}")["Body"].read()
            lines = bodies[i].decode().splitlines()
            assert len(lines) == 2, f"out/shard-{i} must hold 2 lines, got {lines!r}"
            assert lines[0] == expected[i], (
                f"out/shard-{i} must carry the SHA-256 of in/shard-{i}; the container wrote "
                f"{lines[0]!r} and that shard's bytes hash to {expected[i]!r} -- a shard/index "
                f"crossing"
            )
            assert lines[1].startswith(f"IDX={i} "), (
                f"the container's own view of its array index must agree with the key it wrote to; "
                f"out/shard-{i} says {lines[1]!r}"
            )
            hosts.add(lines[1].split("HOST=")[1])
        assert len(hosts) >= 2, (
            f"{_ARRAY_SIZE} children must not all report one container hostname -- that is one "
            f"reused sandbox answering for all of them; got {sorted(hosts)!r}"
        )
        head = s3.head_object(Bucket=bucket, Key="out/shard-0")
        assert head["ContentLength"] == len(bodies[0]), (
            f"out/shard-0 ContentLength {head['ContentLength']!r} != the {len(bodies[0])!r} bytes "
            f"the check read back"
        )

        # ---- the jobRole's prefix scope is enforced, observed by the container ----
        probe = _await_job(bat, probe_id, {"SUCCEEDED", "FAILED"},
                           timeout_s=_budget_s(ctx, _JOB_TIMEOUT_S), ctx=ctx)
        assert probe["status"] == "SUCCEEDED" and (probe.get("container") or {}).get(
            "exitCode") == 0, (
            f"the probe job exits 0 only when its out-of-scope PUT was REFUSED and its in-scope "
            f"report PUT succeeded; exit 3 means S3 ACCEPTED a PUT outside the jobRole's prefix. "
            f"status={probe.get('status')!r} container={probe.get('container')!r} "
            f"logs={_job_log(ctx, log_group, probe)!r}"
        )
        report = s3.get_object(Bucket=bucket, Key="out/probe-report")["Body"].read().decode()
        fields = dict(kv.split("=", 1) for kv in report.split() if "=" in kv)
        assert fields.get("DENIED_CODE") == "AccessDenied", (
            f"a PUT to other/ under a jobRole scoped to out/ must be refused with exactly "
            f"AccessDenied, as parsed by the container out of S3's own <Code> element; the "
            f"container reported {report!r}"
        )
        assert fields.get("DENIED_STATUS") == "403", (
            f"the refusal must carry HTTP 403; the container reported {report!r}"
        )
        assert fields.get("REPORT") == "ok", (
            f"the in-scope control PUT must have succeeded in the same container that was refused "
            f"-- otherwise the denial is a statement about credentials, not about scope; got "
            f"{report!r}"
        )
        denied_space = s3.list_objects_v2(Bucket=bucket, Prefix="other/")
        assert denied_space["KeyCount"] == 0, (
            f"the refused PUT must have left NOTHING under other/, got "
            f"{[o['Key'] for o in denied_space.get('Contents', [])]!r}"
        )

        all_keys = sorted(_keys(s3, bucket))
        want_keys = sorted([f"in/shard-{i}" for i in range(_ARRAY_SIZE)]
                           + [f"out/shard-{i}" for i in range(_ARRAY_SIZE)]
                           + ["out/probe-report"])
        assert all_keys == want_keys, (
            f"whole-bucket negative space: the {len(want_keys)} intended keys and nothing else. "
            f"Unexpected {sorted(set(all_keys) - set(want_keys))!r}, "
            f"missing {sorted(set(want_keys) - set(all_keys))!r}"
        )
        ok = True
    finally:
        # Verified teardown inline: the 60 s cleanup budget cannot cover queue and compute
        # environment deletes that are each polled for minutes. Every step here is also
        # registered on ctx.on_cleanup as the failure-path net.
        leaks = td.run()
        if ok:
            assert not leaks, f"verified teardown did not remove everything: {leaks!r}"
        elif leaks:
            print(f"teardown after a failing body: {leaks!r}", file=sys.stderr)


# ===== the container program (stdlib only; no ENTRYPOINT to fight, nothing installed) =====

_SHARD_PROGRAM = r"""
import hashlib, hmac, json, os, socket, sys, time
import urllib.error, urllib.parse, urllib.request

def sha(b):
    return hashlib.sha256(b).hexdigest()

def creds():
    full = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    uri = full or (("http://169.254.170.2" + rel) if rel else None)
    if not uri:
        print("NO_CREDENTIAL_ENDPOINT")
        sys.exit(5)
    d = json.loads(urllib.request.urlopen(uri, timeout=20).read().decode())
    return d["AccessKeyId"], d["SecretAccessKey"], d["Token"]

def call(method, bucket, region, key, body, ak, sk, tok):
    # A bounded retry on TRANSIENT failures only -- a socket/TLS error or a 429/5xx from S3. With
    # 16 of these running concurrently one of them losing a connection is a fact about the network,
    # not about fidelity, and an unretried one failed a whole 24-child run once. A 403, a 404 or
    # wrong bytes are NOT retried: they are the answers this check is here to read.
    last = None
    for attempt in range(4):
        try:
            st, body_out = one(method, bucket, region, key, body, ak, sk, tok)
        except Exception as exc:
            last = "exception %r" % (exc,)
            time.sleep(2 * (attempt + 1))
            continue
        if st in (429, 500, 502, 503, 504):
            last = "status %s body %r" % (st, body_out[:200])
            time.sleep(2 * (attempt + 1))
            continue
        return st, body_out
    print("TRANSIENT_EXHAUSTED method=%s key=%s last=%s" % (method, key, last))
    return 599, b"transient-exhausted"

def one(method, bucket, region, key, body, ak, sk, tok):
    host = "%s.s3.%s.amazonaws.com" % (bucket, region)
    path = "/" + "/".join(urllib.parse.quote(p, safe="~") for p in key.split("/"))
    amz = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    day = amz[:8]
    ph = sha(body)
    h = {"host": host, "x-amz-content-sha256": ph, "x-amz-date": amz,
         "x-amz-security-token": tok}
    names = sorted(h)
    canon = "\n".join([method, path, "",
                       "".join("%s:%s\n" % (n, h[n]) for n in names),
                       ";".join(names), ph])
    scope = "%s/%s/s3/aws4_request" % (day, region)
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, sha(canon.encode())])
    k = ("AWS4" + sk).encode()
    for part in (day, region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["Authorization"] = ("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                          % (ak, scope, ";".join(names), sig))
    req = urllib.request.Request("https://%s%s" % (host, path),
                                 data=(body if method == "PUT" else None), method=method)
    for n, v in h.items():
        req.add_header(n, v)
    try:
        r = urllib.request.urlopen(req, timeout=60)
        return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()

bucket = os.environ["BUCKET"]
region = os.environ["REGION"]
mode = os.environ["MODE"]
ak, sk, tok = creds()
host = socket.gethostname()

if mode == "shard":
    idx = os.environ["AWS_BATCH_JOB_ARRAY_INDEX"]
    st, data = call("GET", bucket, region, "in/shard-" + idx, b"", ak, sk, tok)
    if st != 200:
        print("GET_FAILED status=%s body=%r" % (st, data[:300]))
        sys.exit(4)
    out = ("%s\nIDX=%s HOST=%s\n" % (sha(data), idx, host)).encode()
    st, resp = call("PUT", bucket, region, "out/shard-" + idx, out, ak, sk, tok)
    if st != 200:
        print("PUT_FAILED status=%s body=%r" % (st, resp[:300]))
        sys.exit(4)
    print("SHARD_OK idx=%s host=%s sha=%s" % (idx, host, sha(data)))
else:
    st, body = call("PUT", bucket, region, "other/shard-0", b"out-of-scope", ak, sk, tok)
    text = body.decode("utf-8", "replace")
    code = text.split("<Code>")[1].split("</Code>")[0] if "<Code>" in text else "NONE"
    over = 200 <= st < 300
    rep = ("DENIED_STATUS=%s DENIED_CODE=%s HOST=%s REPORT=ok\n" % (st, code, host)).encode()
    st2, resp2 = call("PUT", bucket, region, "out/probe-report", rep, ak, sk, tok)
    if st2 != 200:
        print("REPORT_PUT_FAILED status=%s body=%r" % (st2, resp2[:300]))
        sys.exit(4)
    if over:
        print("OVER_PERMISSIVE status=%s" % st)
        sys.exit(3)
    print("DENIED_OK status=%s code=%s" % (st, code))
"""


_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": _PREFIX.rstrip("-"),
    "sim2real": "batch-array-24-shards",
}

_ARRAY_SIZE = 24
_MAX_VCPUS = 4          # 24 children at 0.25 vCPU => 16 concurrent, so 8 must queue
_VCPU = "0.25"

# Bounded deadlines, each with its reason; never a bare sleep standing in for a wait.
_CE_TIMEOUT_S = 600         # a MANAGED/FARGATE CE provisions its own backing ECS cluster
_JQ_TIMEOUT_S = 300         # queue VALID follows CE association
_JOB_TIMEOUT_S = 1500       # 24 children in waves: placement + a ~200 MB public-ECR pull each
_TEARDOWN_TIMEOUT_S = 300   # DISABLED -> settled -> deleted -> gone, per resource

# amazonlinux:2023, pinned BY DIGEST rather than by the moving `2023` tag. Chosen because Batch's
# containerProperties has no entryPoint member and this image has no ENTRYPOINT, and because it
# ships python3 + the stdlib (hashlib/hmac/urllib), so the shard program needs nothing installed
# at run time.
_AL2023 = ("public.ecr.aws/amazonlinux/amazonlinux"
           "@sha256:a0646b8bd35abf5ca3ab94d8cdb5691b9024e19c357531eeefd0ac4762836438")

_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_EXEC_STATEMENTS = [
    {"Effect": "Allow",
     "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage",
                "logs:CreateLogStream", "logs:PutLogEvents"],
     "Resource": "*"}
]


class _Teardown:
    """Every undo, registered twice on purpose: inline in the check's `finally`, in reverse order,
    and on `ctx.on_cleanup` as the failure-path net, because the 60 s cleanup budget cannot
    cover queue and compute-environment deletes that are each polled for minutes.
    """

    def __init__(self, ctx):
        self._ctx = ctx
        self._steps = []

    def add(self, label, fn):
        self._steps.append((label, fn))
        self._ctx.on_cleanup(fn)

    def run(self):
        leaks = []
        for label, fn in reversed(self._steps):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - collected, not swallowed
                leaks.append(f"{label}: {exc!r}")
        return leaks


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown step
        pass


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition",
                ctx=None):
    """Poll probe() until predicate(result); return the final result.

    Raises AssertionError on a deadline miss: a condition that never arrives is a failure.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _paginate(client, op, key, **kwargs):
    """Every page of a List*/Describe*, flattened."""
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _keys(s3, bucket):
    return [o["Key"] for o in _paginate(s3, "list_objects_v2", "Contents", Bucket=bucket)]


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network
    (ctx.network); the run owns and deletes the network.
    """
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _iam_role(ctx, td, kind, statements):
    """A fresh role trusting ecs-tasks with one inline policy; returns (name, arn).

    The inline policy is polled back; trust propagation to ECS is covered by the compute
    environment's provisioning, which every job waits behind.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST), Path="/sim2real/",
        Description="SimParity behavioral: Batch Fargate " + kind,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()])["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))
        if _safe(lambda: iam.get_role(RoleName=name)) is not None:
            raise AssertionError(f"IAM role {name} still exists after DeleteRole")

    td.add(f"iam role {name}", _drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    _poll_until(lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
                lambda r: r is not None, timeout_s=60, interval_s=2,
                description=f"role {name} inline policy readable")
    return name, arn


def _batch_slr(ctx):
    """AWSServiceRoleForBatch, created-or-reused and never deleted: it is account-level, shared
    by every Batch workload, and free to keep.
    """
    iam = ctx.client("iam")
    existing = _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForBatch"))
    if existing:
        return existing["Role"]["Arn"]
    _safe(lambda: iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com"))
    role = _poll_until(lambda: _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForBatch")),
                       lambda r: r is not None, timeout_s=120, interval_s=1,
                       description="AWSServiceRoleForBatch readable")
    return role["Role"]["Arn"]


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(
        computeEnvironments=[name]).get("computeEnvironments", [])
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_ce(bat, name, statuses, timeout_s=_CE_TIMEOUT_S, interval_s=1, ctx=None):
    return _poll_until(lambda: _describe_ce(bat, name),
                       lambda ce: ce is not None and ce.get("status") in statuses,
                       timeout_s=timeout_s, interval_s=interval_s, ctx=ctx,
                       description=f"compute environment {name} status in {sorted(statuses)}")


def _await_jq(bat, name, statuses, timeout_s=_JQ_TIMEOUT_S, interval_s=1, ctx=None):
    return _poll_until(lambda: _describe_jq(bat, name),
                       lambda jq: jq is not None and jq.get("status") in statuses,
                       timeout_s=timeout_s, interval_s=interval_s, ctx=ctx,
                       description=f"job queue {name} status in {sorted(statuses)}")


def _await_job(bat, job_id, statuses, timeout_s=_JOB_TIMEOUT_S, interval_s=2, ctx=None):
    return _poll_until(lambda: _describe_job(bat, job_id),
                       lambda j: j is not None and j.get("status") in statuses,
                       timeout_s=timeout_s, interval_s=interval_s, ctx=ctx,
                       description=f"batch job {job_id} status in {sorted(statuses)}")


def _teardown_jobs(bat, job_ids):
    """Terminate every job, then wait for each to be terminal: DeleteJobQueue fails while the
    queue holds a non-terminal job, and DeleteComputeEnvironment while a queue references it.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason=_PREFIX + "cleanup"))
    for jid in list(job_ids):
        _poll_until(lambda jid=jid: _describe_job(bat, jid),
                    lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
                    timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=2,
                    description=f"job {jid} terminal before queue teardown")


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue (retried) -> poll gone.

    DeleteJobQueue raises ClientException for a still-draining queue that accepts the same call
    seconds later.
    """
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _await_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    for _ in range(32):
        if _safe(lambda: bat.delete_job_queue(jobQueue=name)) is not None:
            break
        time.sleep(2)
    _poll_until(lambda: _describe_jq(bat, name), lambda jq: jq is None,
                timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=2,
                description=f"job queue {name} gone")


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment (retried) -> poll gone."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _await_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    for _ in range(32):
        if _safe(lambda: bat.delete_compute_environment(computeEnvironment=name)) is not None:
            break
        time.sleep(2)
    _poll_until(lambda: _describe_ce(bat, name), lambda ce: ce is None,
                timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=2,
                description=f"compute environment {name} gone")


def _fargate_stack(ctx, bat, td, max_vcpus=4):
    """MANAGED/FARGATE compute environment + ENABLED queue, both polled VALID. Returns the queue.

    FARGATE has no minvCpus floor, so an idle CE bills nothing; maxvCpus only caps concurrency.
    """
    subnets, sg = _fargate_network(ctx)
    ce_name = ctx.unique_name(_PREFIX + "ce-fg-")
    ce_arn = bat.create_compute_environment(
        computeEnvironmentName=ce_name, type="MANAGED", state="ENABLED",
        serviceRole=_batch_slr(ctx),
        computeResources={"type": "FARGATE", "maxvCpus": max_vcpus,
                          "subnets": subnets[:3], "securityGroupIds": [sg]},
        tags=dict(_MANAGED_TAGS))["computeEnvironmentArn"]
    td.add(f"batch compute environment {ce_name}", lambda: _teardown_ce(bat, ce_name))
    ce = _await_ce(bat, ce_name, {"VALID", "INVALID"}, timeout_s=_budget_s(ctx, _CE_TIMEOUT_S),
                   ctx=ctx)
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} did not become VALID: status={ce.get('status')!r} "
        f"statusReason={ce.get('statusReason')!r}")

    jq_name = ctx.unique_name(_PREFIX + "jq-")
    bat.create_job_queue(
        jobQueueName=jq_name, state="ENABLED", priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS))
    td.add(f"batch job queue {jq_name}", lambda: _teardown_jq(bat, jq_name))
    jq = _await_jq(bat, jq_name, {"VALID", "INVALID"}, timeout_s=_budget_s(ctx, _JQ_TIMEOUT_S),
                   ctx=ctx)
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} did not become VALID: status={jq.get('status')!r} "
        f"statusReason={jq.get('statusReason')!r}")
    return jq_name


def _register_jd(ctx, bat, td, command, *, exec_role_arn, image, log_group=None,
                 job_role_arn=None, vcpu="0.25", memory="512", environment=None):
    """Register a container/FARGATE job definition. Returns "<name>:<revision>"."""
    name = ctx.unique_name(_PREFIX + "jd-")
    container = {
        "image": image,
        "command": command,
        "executionRoleArn": exec_role_arn,
        "resourceRequirements": [{"type": "VCPU", "value": vcpu},
                                 {"type": "MEMORY", "value": memory}],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
        "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
    }
    if log_group is not None:
        container["logConfiguration"] = {
            "logDriver": "awslogs",
            "options": {"awslogs-group": log_group, "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "batch"}}
    if job_role_arn is not None:
        container["jobRoleArn"] = job_role_arn
    if environment is not None:
        container["environment"] = environment
    rev = bat.register_job_definition(
        jobDefinitionName=name, type="container", platformCapabilities=["FARGATE"],
        containerProperties=container, tags=dict(_MANAGED_TAGS))["revision"]
    ref = f"{name}:{rev}"

    def _drop():
        _swallow(lambda: bat.deregister_job_definition(jobDefinition=ref))
        # Batch registers an ECS task definition of its own, in a family named after the job
        # definition, the first time it runs a Fargate job, and DeregisterJobDefinition does not
        # remove it, so those task definitions are deregistered and deleted here.
        ecs = ctx.client("ecs")
        for arn in _paginate(ecs, "list_task_definitions", "taskDefinitionArns",
                             familyPrefix=name, status="ACTIVE"):
            _swallow(lambda a=arn: ecs.deregister_task_definition(taskDefinition=a))
            _swallow(lambda a=arn: ecs.delete_task_definitions(taskDefinitions=[a]))
        left = _paginate(ecs, "list_task_definitions", "taskDefinitionArns",
                         familyPrefix=name, status="ACTIVE")
        if left:
            raise AssertionError(f"Batch-created ECS task definitions still ACTIVE: {left!r}")

    td.add(f"batch job definition {ref}", _drop)
    return ref


def _submit(ctx, bat, td, queue, job_def, **kwargs):
    """SubmitJob with teardown registered from THIS response's jobId, at submit time."""
    name = kwargs.pop("jobName", None) or ctx.unique_name(_PREFIX + "job-")
    jid = bat.submit_job(jobName=name, jobQueue=queue, jobDefinition=job_def, **kwargs)["jobId"]
    td.add(f"batch job {jid}", lambda: _teardown_jobs(bat, [jid]))
    return jid


_JOB_STATUSES = ("SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED")


def _describe_children(bat, array_job_id):
    """Every child of an array job with full detail, across every status.

    ListJobs defaults jobStatus to RUNNING, so each status is named; JobSummary lacks taskArn and
    attempts, so ids go back through DescribeJobs, at most 100 at a time.
    """
    ids = []
    for status in _JOB_STATUSES:
        for js in _paginate(bat, "list_jobs", "jobSummaryList",
                            arrayJobId=array_job_id, jobStatus=status):
            if js["jobId"] not in ids:
                ids.append(js["jobId"])
    out = []
    for i in range(0, len(ids), 20):
        out.extend(bat.describe_jobs(jobs=ids[i:i + 20]).get("jobs", []))
    return out


def _create_log_group(ctx, td):
    """A log group this check owns outright, so teardown is one call that takes the streams too,
    and the shared /aws/batch/job group is never read from or deleted.
    """
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))

    def _drop():
        _swallow(lambda: logs.delete_log_group(logGroupName=name))
        left = _safe(lambda: logs.describe_log_groups(logGroupNamePrefix=name))
        if left and left.get("logGroups"):
            raise AssertionError(f"log group {name} still present after DeleteLogGroup")

    td.add(f"log group {name}", _drop)
    return name


def _job_log(ctx, group, job):
    """Every message a job's container wrote, for an assertion's failure message."""
    logs = ctx.client("logs")
    stream = (job.get("container") or {}).get("logStreamName")
    if not stream:
        return []
    resp = _safe(lambda: logs.get_log_events(logGroupName=group, logStreamName=stream,
                                             startFromHead=True))
    return [e.get("message", "") for e in (resp or {}).get("events", [])]


def _create_bucket(ctx, td):
    """A bucket this check owns; teardown paginates every object out before DeleteBucket."""
    s3 = ctx.client("s3")
    name = ctx.unique_name(_PREFIX + "shards-")
    kwargs = dict(Bucket=name)
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop():
        from botocore.exceptions import ClientError

        try:
            keys = _keys(s3, name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
                raise
            return  # the inline teardown already removed it; this is the failure-path net
        for key in keys:
            _swallow(lambda k=key: s3.delete_object(Bucket=name, Key=k))
        _swallow(lambda: s3.delete_bucket(Bucket=name))
        if _safe(lambda: s3.head_bucket(Bucket=name)) is not None:
            raise AssertionError(f"S3 bucket {name} still present after DeleteBucket")

    td.add(f"s3 bucket {name}", _drop)
    _swallow(lambda: s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": k, "Value": v}
                                         for k, v in _MANAGED_TAGS.items()]}))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
