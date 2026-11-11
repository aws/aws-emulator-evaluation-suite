"""cdk-bootstrapped-container-service-workflow."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-bootstrapped-container-service-workflow"
GROUP = "iac-long-horizon"
SERVICES = ["cloudwatch", "ecr", "ecs", "elbv2", "logs"]

_APP_DIR = Path(__file__).parent / "deployments" / "container_service_cdk"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "dp:native",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A bootstrapped `cdk deploy` publishes a container image asset the ALB-fronted service serves;
    logs, a metric filter and an alarm follow, an ECR-denied variant never starts, an env change
    updates the service in place without a re-push, and destroy removes stacks and toolkit.
    """
    legs = _Legs(ctx, total=11)
    _require_container_builder(ctx)
    prefix = _xname(ctx, "cdkstk")
    main_stack, broken_stack = f"{prefix}-main", f"{prefix}-broken"
    marker = ctx.unique_name("mk")[:14]
    context = {
        "stack_prefix": prefix,
        "greeting": "hello",
        "site_marker": marker,
        "metric_namespace": f"sim2real/xsvc/{ctx.unique_name('')[:10]}",
        "ingress_cidrs": ",".join(ctx.ingress_cidrs()),
    }

    app = _cdk_prepare(ctx, _APP_DIR)
    legs.hard("bootstrap", lambda: _bootstrap_cdk(ctx, legs, app, context=context, want_repo=True))
    dep = legs.hard(
        "deploy",
        lambda: _deploy_cdk_bootstrapped(
            ctx,
            legs,
            app,
            stack=main_stack,
            asm_name="asm1",
            context=context,
            timeout_s=1800.0,
            want_repo=True,
        ),
    )

    legs.step("asset", lambda: _assert_image_asset_published(ctx, dep))
    legs.step("wiring", lambda: _assert_alb_serves_the_image(ctx, legs, dep, greeting="hello"))
    # The denial leg shares only the cluster with the logs -> metrics -> alarm chain, so it runs
    # beside it instead of after the alarm's evaluation wait.
    denial = _start(
        lambda: legs.step(
            "denial",
            lambda: _assert_broken_variant_denied(ctx, legs, app, dep, broken_stack, context),
            requires=("wiring",),
        )
    )
    try:
        legs.step("logs", lambda: _assert_container_log_stream(ctx, legs, dep), requires=("wiring",))
        legs.step("metrics", lambda: _assert_metric_datapoint(ctx, legs, dep), requires=("logs",))
        legs.step("alarm", lambda: _assert_alarms(ctx, legs, dep), requires=("metrics",))
    finally:
        denial()
    legs.step(
        "drift",
        lambda: _assert_env_change_modifies(ctx, legs, app, dep, context),
        requires=("wiring",),
    )
    legs.step(
        "teardown",
        lambda: _assert_destroy_stops_serving(ctx, legs, app, dep, broken_stack),
        requires=("wiring",),
    )
    # Deliberately NOT gated on `teardown`: attempting it unconditionally keeps the toolkit from
    # leaking.
    legs.step("toolkit", lambda: _destroy_toolkit(ctx, legs, app))
    legs.verdict()
_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to a single line, so a leg's evidence cannot displace the summary line."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised ONCE at the end.

    The summary is the LAST line of the message on purpose.
    """

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        #: Legs that FAILED. Drives the final raise.
        self._failed: set[str] = set()
        #: Legs that did not PASS -- failed OR blocked. Drives `requires` gating; separate from
        #: `_failed` so a leg whose prerequisite was BLOCKED is blocked too.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a run killed by the budget still leaves a trail.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when a prerequisite already failed.

        BLOCKED rather than FAIL so one broken hop does not count as a failure per downstream leg.
        """
        blocked_by = [r for r in requires if r in self._not_passed]
        if blocked_by:
            self._not_passed.add(name)
            self._record(name, "BLOCKED", f"requires {','.join(blocked_by)}")
            return None
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001 -- recorded, then re-raised in aggregate
            self._failed.add(name)
            self._not_passed.add(name)
            self._record(name, "FAIL", _one_line(exc))
            return None
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def hard(self, name: str, fn):
        """A leg with nothing gradeable downstream (deploy, bootstrap): raise immediately rather
        than reporting N derived failures for a stack that never came up."""
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001
            self._record(name, "FAIL", _one_line(exc))
            raise AssertionError(self._summary(name, _one_line(exc))) from exc
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def never_reached(self, what: str, waited_s: float):
        """Fail for a state the target accepted and never reached."""
        raise AssertionError(f"{what}; not reached after {waited_s:.0f}s of polling")

    def _summary(self, headline_leg: str, headline_evidence: str) -> str:
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        cells = " ".join(f"{n}={v}" for n, v, _ in self._rows)
        # The cells are truncated, NEVER the headline, which must survive intact.
        head = _one_line(f"WORKFLOW FAILED at {headline_leg}: {headline_evidence}", _HEADLINE_CAP)
        return f"LEGS {n_pass}/{self._total} PASS | {cells[:900]}\n{head}"

    def verdict(self) -> None:
        """Raise once if any leg failed. Call as the LAST statement of run()."""
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        print(f"[legs] {n_pass}/{self._total} PASS", flush=True)
        if not self._failed:
            return
        leg, _, evidence = next(r for r in self._rows if r[1] == "FAIL")
        raise AssertionError(self._summary(leg, evidence))


# --- names, polling ----------------------------------------------------------
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _start(fn):
    """Run *fn* on a thread; the returned join() waits, re-raises what it raised, returns its value."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 -- re-raised by join()
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    def join():
        thread.join()
        if "error" in box:
            raise box["error"]
        return box.get("value")

    return join


def _poll_until(
    probe,
    predicate,
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
    description: str = "condition",
    legs: Any = None,
):
    """Poll until *predicate* holds, else report a NON-CONVERGENCE (never a timeout).

    Passing ``legs`` routes exhaustion through ``_Legs.never_reached`` and caps the deadline by
    the run's remaining budget.
    """
    started = time.monotonic()
    left = None if legs is None else legs._ctx.time_left()
    deadline = started + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    waited = time.monotonic() - started
    if legs is not None:
        legs.never_reached(f"{description} not observed (last={_one_line(last, 60)})", waited)
    raise AssertionError(f"{description} not observed in {timeout_s:.0f}s (last={_one_line(last, 90)})")


def _swallow(fn, *codes: str):
    """Call *fn*, treating the named ClientError codes as success (idempotent teardown)."""
    try:
        return fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in codes:
            return None
        raise


# --- the bootstrapped CDK deploy path ---------------------------------------
#
# `cdk bootstrap` -> `cdk synth` -> `cdk deploy --require-approval never` (cdk-assets publishes
# every asset) -> outputs read back through CloudFormation -> `cdk destroy --force`.
# The toolkit is minted PER RUN (`--qualifier` plus `--toolkit-stack-name`) instead of the shared
# `CDKToolkit`/`hnb659fds`, so the bootstrap is always performed, concurrent deploys in the same
# account are not disturbed, and the toolkit can be destroyed. The qualifier must be a short
# alphanumeric token, so only the toolkit STACK name carries the `sim2real-` prefix.
_CDK_QUALIFIER_CONTEXT = "@aws-cdk/core:bootstrapQualifier"
_CDK_MIN_BOOTSTRAP_VERSION = 6


def _version_param(qualifier: str) -> str:
    """The SSM parameter `cdk deploy`'s CheckBootstrapVersion rule reads."""
    return f"/cdk-bootstrap/{qualifier}/version"
# --ci keeps the CLI off a TTY; --no-notices / --no-version-reporting keep it off the network for
# anything that is not the target.
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")
_STACK_HEALTHY = frozenset({"CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"})
_DESTROY_BUDGET_S = 1800.0


def _asset_bucket(qualifier: str, account: str, region: str) -> str:
    return f"cdk-{qualifier}-assets-{account}-{region}"


def _asset_repo(qualifier: str, account: str, region: str) -> str:
    return f"cdk-{qualifier}-container-assets-{account}-{region}"


def _stack_status(cfn, name: str) -> str | None:
    """The stack's status, or None when it does not exist (CloudFormation says so with a
    ValidationError, not a typed absence)."""
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") or ""
        if code in {"ValidationError", "StackNotFoundException"} and "does not exist" in str(exc):
            return None
        if code == "StackNotFoundException":
            return None
        raise


def _stack_outputs(cfn, name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _sub_env(text: str, account: str, region: str) -> str:
    return text.replace("${AWS::AccountId}", account).replace("${AWS::Region}", region)


def _read_assets(asm: Path, stack: str, account: str, region: str) -> dict[str, list[dict]]:
    """The cloud assembly's OWN asset manifest for *stack* (`<stack>.assets.json`).

    `zip` file assets are the app's directory assets; the `file`-packaged one is the stack template.
    """
    path = asm / f"{stack}.assets.json"
    doc = json.loads(path.read_text()) if path.exists() else {}
    files: list[dict] = []
    for digest, spec in (doc.get("files") or {}).items():
        source = spec.get("source") or {}
        for dest in (spec.get("destinations") or {}).values():
            files.append(
                {
                    "hash": digest,
                    # The assembly's own label ("Fn/Code", "Transform/Code", "<stack> Template") —
                    # the only thing that tells two zip assets apart, since both stage as
                    # `asset.<hash>` and the hash is exactly what a content change moves.
                    "display": spec.get("displayName", ""),
                    "packaging": source.get("packaging", ""),
                    "source": source.get("path", ""),
                    "bucket": _sub_env(dest.get("bucketName", ""), account, region),
                    "key": _sub_env(dest.get("objectKey", ""), account, region),
                }
            )
    images: list[dict] = []
    for digest, spec in (doc.get("dockerImages") or {}).items():
        source = spec.get("source") or {}
        for dest in (spec.get("destinations") or {}).values():
            images.append(
                {
                    "hash": digest,
                    "display": spec.get("displayName", ""),
                    "source": source.get("directory", ""),
                    "repo": _sub_env(dest.get("repositoryName", ""), account, region),
                    "tag": dest.get("imageTag", ""),
                }
            )
    return {"files": files, "images": images}


def _zip_assets(assets: dict[str, list[dict]]) -> list[dict]:
    """Only the app's OWN directory assets — the staged stack template is not one of them."""
    return [f for f in assets.get("files") or [] if f.get("packaging") == "zip"]


#: Assets cdk-assets stages for aws-cdk-lib ITSELF rather than for this app (a BucketDeployment's
#: handler and CLI layer, the auto-delete-objects provider). They are shared by every CDK app in
#: the account, so they are left behind deliberately; everything the app itself owns is purged.
_LIBRARY_ASSET_MARKERS = ("Custom::", "AwsCliLayer")


def _owned_assets(assets: dict[str, list[dict]], kind: str) -> list[dict]:
    """The *kind* ("files"/"images") assets this app owns, excluding aws-cdk-lib's own."""
    return [
        a
        for a in assets.get(kind) or []
        if not any(marker in (a.get("display") or "") for marker in _LIBRARY_ASSET_MARKERS)
    ]


def _template_asset(assets: dict[str, list[dict]]) -> dict:
    """The staged stack TEMPLATE object. Selected by the assembly's label, not by packaging: a
    BucketDeployment stages its CLI layer as a `file` asset too, so "the one non-zip asset" is not
    the template."""
    matches = [
        f
        for f in assets.get("files") or []
        if (f.get("display") or "").endswith("Template")
    ]
    assert len(matches) == 1, f"expected one staged template, assembly declares {len(matches)}"
    return matches[0]


def _asset_named(assets: dict[str, list[dict]], display: str) -> dict:
    """The one zip asset the assembly labelled *display* (e.g. "Transform/Code")."""
    matches = [f for f in _zip_assets(assets) if f.get("display") == display]
    assert len(matches) == 1, f"expected one {display!r} asset, assembly declares {len(matches)}"
    return matches[0]


def _run_cdk(legs, app: dict, argv: list[str], *, what: str, timeout_s: float):
    """Run the cdk CLI in the staged workdir. Returns the CompletedProcess; never raises on rc.

    A wall-clock overrun is reported through ``legs.never_reached``, never via the exception text.
    """
    cmd = ["cdk", *argv, *_CDK_FLAGS]
    print(f"[cdk] {' '.join(cmd[:6])} ... (budget {timeout_s:.0f}s)", flush=True)
    try:
        return subprocess.run(
            cmd,
            cwd=str(app["work"]),
            env=app["env"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        legs.never_reached(f"{what} did not finish inside its wall-clock budget", timeout_s)
    except OSError as exc:  # the CLI vanished between the availability probe and here
        raise AssertionError(f"cdk CLI not runnable: {type(exc).__name__}") from None


def _cdk_failed(what: str, done) -> None:
    """Raise for a non-zero `cdk` rc, with the tail of its output."""
    tail = _one_line(f"{done.stderr or ''} {done.stdout or ''}", 170)
    raise AssertionError(f"{what} rc={done.returncode}: {tail}")


def _cdk_prepare(ctx, app_dir) -> dict:
    """Stage a private copy of the CDK app and the child environment it runs under."""
    require_tools("cdk")
    ctx.verify_account_safety()
    work = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdk-"))
    shutil.copytree(
        Path(app_dir),
        work,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("cdk.out", ".venv", "__pycache__", "node_modules"),
    )
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    account = ctx.client("sts").get_caller_identity()["Account"]
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_ACCOUNT"] = account
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DISABLE_VERSION_CHECK"] = "1"
    # A leading letter plus 8 of `unique_name`'s 12 hex chars: the CLI wants a short alphanumeric
    # qualifier that is unique per bootstrap stack.
    return {
        "work": work,
        "env": env,
        "account": account,
        "owned": {},
        "qualifier": "s" + ctx.unique_name("")[:8],
        "toolkit_stack": _xname(ctx, "cdktk"),
    }


def _bootstrap_argv(
    ctx, app: dict, stack: str, qualifier: str, context: dict[str, str] | None
) -> list[str]:
    """argv for `cdk bootstrap`, carrying the SAME context the synth gets.

    `cdk bootstrap` synthesizes the app, and the app cannot be constructed without its context.
    """
    argv = [
        "bootstrap",
        f"aws://{app['account']}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        stack,
        "--tags",
        f"{_MANAGED_TAG_KEY}=true",
    ]
    # The qualifier goes in as context too, exactly as _cdk_synth does it: the app's stacks resolve
    # their synthesizer from this key, so bootstrap and deploy must agree on it.
    for key, value in {_CDK_QUALIFIER_CONTEXT: qualifier, **(context or {})}.items():
        argv.extend(["--context", f"{key}={value}"])
    return argv


def _bootstrap_cdk(
    ctx, legs, app: dict, *, context: dict[str, str] | None = None,
    want_repo: bool = False,
) -> str:
    """Create THIS run's own CDK bootstrap environment and assert what `cdk deploy` will look for.

    The boto3 DescribeStacks is a preflight separating a target that is not listening from one
    that cannot bootstrap.
    """
    cfn = ctx.client("cloudformation")
    stack, qualifier = app["toolkit_stack"], app["qualifier"]
    status = _stack_status(cfn, stack)
    # Idempotent WITHIN a run, strict ACROSS runs: the deploy helper calls this again after the
    # bootstrap leg, but a toolkit left by a DIFFERENT run must still trip the assertion below.
    if app.get("bootstrapped"):
        assert status in _STACK_HEALTHY, (
            f"{stack} was bootstrapped by this run but now reads {status!r}; the toolkit must be "
            f"healthy for the asset publish that follows"
        )
        return f"reused {stack} qualifier {qualifier} (bootstrapped earlier this run)"
    assert status is None, (
        f"{stack} already exists ({status}) — this name is minted per run, so a collision means "
        "the toolkit is being shared and the parity this qualifier buys is gone"
    )
    # Registered BEFORE the create so a failure part-way through still tears down what landed. LIFO
    # runs it after the app stacks' cleanups, which need the toolkit's publish roles to delete.
    ctx.on_cleanup(lambda: _sweep_toolkit(ctx, app))
    done = _run_cdk(
        legs,
        app,
        _bootstrap_argv(ctx, app, stack, qualifier, context),
        what="cdk bootstrap",
        timeout_s=900.0,
    )
    if done.returncode != 0:
        _cdk_failed("cdk bootstrap", done)
    _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: s in _STACK_HEALTHY,
        timeout_s=600.0,
        interval_s=2.0,
        description=f"{stack} reaching CREATE_COMPLETE",
        legs=legs,
    )
    # Assert what `cdk deploy` will itself look for, rather than trusting the CLI's exit code: the
    # SSM version parameter (the CheckBootstrapVersion rule reads it) and the staging bucket.
    version = ctx.client("ssm").get_parameter(Name=_version_param(qualifier))["Parameter"]["Value"]
    assert int(version) >= _CDK_MIN_BOOTSTRAP_VERSION, (
        f"bootstrap version {version} predates the asset-publishing roles"
    )
    bucket = _asset_bucket(qualifier, app["account"], ctx.region)
    ctx.client("s3").head_bucket(Bucket=bucket)
    detail = f"created {stack} v{version} qualifier {qualifier}, bucket {bucket}"
    if want_repo:
        repo = _asset_repo(qualifier, app["account"], ctx.region)
        ctx.client("ecr").describe_repositories(repositoryNames=[repo])
        detail += f", repo {repo}"
    app["bootstrapped"] = True
    return detail


def _empty_asset_store(ctx, app: dict) -> str:
    """Empty the staging bucket and the asset repository so the toolkit stack can be deleted:
    CloudFormation refuses a non-empty bucket or an image-holding repository."""
    qualifier, account = app["qualifier"], app["account"]
    bucket, objects = _asset_bucket(qualifier, account, ctx.region), 0
    s3 = ctx.client("s3")
    # Versions AND delete markers: the staging bucket is versioned, so a plain delete_object
    # leaves the payload addressable under a marker.
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in [*(page.get("Versions") or []), *(page.get("DeleteMarkers") or [])]:
                s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
                objects += 1
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucket", "404"}:
            raise
    repo, images = _asset_repo(qualifier, account, ctx.region), 0
    ecr = ctx.client("ecr")
    try:
        for page in ecr.get_paginator("list_images").paginate(repositoryName=repo):
            ids = page.get("imageIds") or []
            if ids:
                ecr.batch_delete_image(repositoryName=repo, imageIds=ids)
                images += len(ids)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise
    return f"{objects} object(s), {images} image(s)"


def _destroy_toolkit(ctx, legs, app: dict) -> str:
    """Delete this run's bootstrap environment and prove it is gone. A GRADED leg, not a cleanup,
    because a stack delete does not fit in the cleanup budget. Evidence is the SSM version
    parameter, which `cdk deploy` reads to decide the environment exists.
    """
    stack, qualifier = app["toolkit_stack"], app["qualifier"]
    cfn = ctx.client("cloudformation")
    if _stack_status(cfn, stack) is None:
        return f"{stack} already gone"
    emptied = _empty_asset_store(ctx, app)
    cfn.delete_stack(StackName=stack)
    _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: s in (None, "DELETE_COMPLETE"),
        timeout_s=900.0,
        interval_s=2.0,
        description=f"{stack} deletion",
        legs=legs,
    )
    left = _swallow(
        lambda: ctx.client("ssm").get_parameter(Name=_version_param(qualifier)),
        "ParameterNotFound",
    )
    assert left is None, (
        f"{stack} reports deleted but {_version_param(qualifier)} survives — `cdk deploy` would "
        "still read this environment as bootstrapped"
    )
    # The bootstrap template retains the staging bucket and asset repository on stack delete; they
    # are already empty, and NoSuchBucket/RepositoryNotFoundException means a target did not retain them.
    bucket = _asset_bucket(qualifier, app["account"], ctx.region)
    _swallow(lambda: ctx.client("s3").delete_bucket(Bucket=bucket), "NoSuchBucket")
    survives = _swallow(lambda: ctx.client("s3").head_bucket(Bucket=bucket), "404", "NoSuchBucket")
    assert survives is None, f"staging bucket {bucket} survives its own delete_bucket call"
    repo = _asset_repo(qualifier, app["account"], ctx.region)
    _swallow(
        lambda: ctx.client("ecr").delete_repository(repositoryName=repo),
        "RepositoryNotFoundException",
    )
    return f"{stack} deleted, {emptied} purged, staging bucket and asset repository removed"


def _sweep_toolkit(ctx, app: dict) -> None:
    """Cleanup net for the toolkit when the graded leg never got to it: delete it and confirm the
    stack is gone inside what the cleanup budget leaves after the app-stack nets."""
    stack = app["toolkit_stack"]
    try:
        if _stack_status(ctx.client("cloudformation"), stack) is None:
            return
        _empty_asset_store(ctx, app)
        ctx.client("cloudformation").delete_stack(StackName=stack)
        # The template retains the emptied staging bucket and asset repository; remove them here.
        bucket = _asset_bucket(app["qualifier"], app["account"], ctx.region)
        _swallow(lambda: ctx.client("s3").delete_bucket(Bucket=bucket), "NoSuchBucket")
        repo = _asset_repo(app["qualifier"], app["account"], ctx.region)
        _swallow(
            lambda: ctx.client("ecr").delete_repository(repositoryName=repo),
            "RepositoryNotFoundException",
        )
        final = _wait_stack_gone(ctx, stack, timeout_s=_TOOLKIT_WAIT_BUDGET_S)
        if final is not None and final != "DELETE_COMPLETE":
            raise RuntimeError(f"toolkit stack {stack} is {final} {_TOOLKIT_WAIT_BUDGET_S:.0f}s after delete_stack")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket", "RepositoryNotFoundException"):
            raise RuntimeError(f"could not remove bootstrap toolkit {stack}: {_one_line(exc)} — its staging "
                "bucket, asset repository and five IAM roles remain in the account") from exc


def _cdk_synth(ctx, legs, app: dict, *, asm_name: str, context: dict[str, str]) -> Path:
    """`cdk synth` into a named assembly dir. A synth runs locally, so its failure is an app
    defect and never marked as a target verdict."""
    asm = app["work"] / asm_name
    argv = ["synth", "--output", str(asm)]
    # The synthesizer reads the qualifier from CONTEXT, so the asset names and the
    # CheckBootstrapVersion rule address THIS run's toolkit rather than the account-wide default.
    for key, value in {_CDK_QUALIFIER_CONTEXT: app["qualifier"], **context}.items():
        argv.extend(["--context", f"{key}={value}"])
    done = _run_cdk(legs, app, argv, what=f"cdk synth ({asm_name})", timeout_s=420.0)
    if done.returncode != 0:
        raise AssertionError(
            f"cdk synth failed (local app defect, not a target verdict): "
            f"{_one_line(done.stderr or done.stdout, 200)}"
        )
    return asm


def _cdk_deploy_stack(ctx, legs, app: dict, *, stack: str, asm: Path, timeout_s: float = 1800.0) -> dict:
    """`cdk deploy --require-approval never` for one stack of a pre-synthesized assembly.

    Teardown is registered BEFORE the deploy runs: a deploy cut short still leaves a stack behind.
    """
    cfn = ctx.client("cloudformation")
    rec = app["owned"].setdefault(stack, {"gone": False, "assets": {"files": [], "images": []}})
    if not rec.get("registered"):
        rec["registered"] = True
        ctx.on_cleanup(
            lambda: _cdk_destroy(
                ctx,
                app,
                stack,
                destroy_timeout_s=_CLEANUP_DESTROY_BUDGET_S,
                wait_timeout_s=_CLEANUP_WAIT_BUDGET_S,
            )
        )
    rec["asm"] = asm
    published = _read_assets(asm, stack, app["account"], ctx.region)
    # Union across deploys: a redeploy from a new assembly publishes NEW keys and the old ones are
    # still ours to remove, so teardown has to know about both.
    for kind in ("files", "images"):
        known = {(a.get("key") or a.get("tag")) for a in rec["assets"][kind]}
        rec["assets"][kind].extend(
            a for a in published[kind] if (a.get("key") or a.get("tag")) not in known
        )
    done = _run_cdk(
        legs,
        app,
        [
            "deploy",
            "--app",
            str(asm),
            stack,
            "--require-approval",
            "never",
            "--tags",
            f"{_MANAGED_TAG_KEY}=true",
        ],
        what=f"cdk deploy {stack}",
        timeout_s=timeout_s,
    )
    if done.returncode != 0:
        _cdk_failed(f"cdk deploy {stack}", done)
    status = _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: s in _STACK_HEALTHY,
        timeout_s=600.0,
        interval_s=2.0,
        description=f"stack {stack} reaching a complete state",
        legs=legs,
    )
    outputs = _stack_outputs(cfn, stack)
    return {
        "stack": stack,
        "status": status,
        "outputs": outputs,
        "assets": published,
        "asm": asm,
        "record": rec,
    }


def _deploy_cdk_bootstrapped(
    ctx,
    legs,
    app: dict,
    *,
    stack: str,
    asm_name: str,
    context: dict[str, str],
    timeout_s: float = 1800.0,
    want_repo: bool = False,
) -> dict:
    """A bootstrapped, asset-bearing `cdk deploy`: ensure the bootstrap, synthesize, deploy the
    stack with every asset published, and read the outputs back. One call so the deploy leg owns
    the synth too.
    """
    _bootstrap_cdk(ctx, legs, app, context=context, want_repo=want_repo)
    asm = _cdk_synth(ctx, legs, app, asm_name=asm_name, context=context)
    return _cdk_deploy_stack(ctx, legs, app, stack=stack, asm=asm, timeout_s=timeout_s)


def _delete_all_versions(s3, bucket: str, key: str) -> None:
    """Remove every version and delete marker of *key*. The bootstrap staging bucket is versioned,
    so a plain delete_object leaves the payload behind under a delete marker."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=key):
        for entry in [*(page.get("Versions") or []), *(page.get("DeleteMarkers") or [])]:
            if entry["Key"] != key:
                continue
            s3.delete_object(Bucket=bucket, Key=key, VersionId=entry["VersionId"])


def _purge_assets(ctx, assets: dict[str, list[dict]]) -> None:
    """Delete exactly the objects and images THIS check published, and say so when one survives.

    cdk-assets uploads out of band, so assets are not stack resources and `cdk destroy` leaves them.
    """
    s3 = ctx.client("s3")
    for asset in _owned_assets(assets, "files"):
        bucket, key = asset.get("bucket"), asset.get("key")
        if not bucket or not key:
            continue
        try:
            try:
                s3.delete_object(Bucket=bucket, Key=key)
                _delete_all_versions(s3, bucket, key)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucket", "NoSuchKey"}:
                    raise
        except Exception as exc:  # noqa: BLE001 -- teardown reports, never raises
            print(
                f"published file asset s3://{bucket}/{key} was not removed "
                f"({type(exc).__name__}: {_one_line(exc, 90)}) — it stays in the SHARED bootstrap "
                "staging bucket, which no name-prefix cleanup matches",
                file=sys.stderr,
            )
    images = _owned_assets(assets, "images")
    if not images:
        return
    ecr = ctx.client("ecr")
    for image in images:
        repo, tag = image.get("repo"), image.get("tag")
        if not repo or not tag:
            continue
        try:
            try:
                resp = ecr.batch_delete_image(repositoryName=repo, imageIds=[{"imageTag": tag}])
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
                    raise
                resp = {}
            failures = (resp or {}).get("failures") or []
            failures = [f for f in failures if f.get("failureCode") != "ImageNotFound"]
            if failures:
                raise AssertionError(_one_line(failures, 90))
        except Exception as exc:  # noqa: BLE001 -- teardown reports, never raises
            print(
                f"published image asset {repo}:{tag} was not removed "
                f"({type(exc).__name__}: {_one_line(exc, 90)}) — the layers stay in the SHARED "
                "bootstrap asset repository and are billed as storage",
                file=sys.stderr,
            )


def _wait_stack_gone(ctx, stack: str, *, timeout_s: float = 900.0, interval_s: float = 2.0) -> str | None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status: str | None = "UNKNOWN"
    while time.monotonic() < deadline:
        status = _stack_status(cfn, stack)
        if status is None or status in {"DELETE_COMPLETE", "DELETE_FAILED"}:
            return status
        time.sleep(interval_s)
    return status


#: The teardown-via-cleanup path runs under the suite's shorter 900s cleanup budget, not the
#: 1800s the graded "teardown" leg gets; split across the `cdk destroy` subprocess and the
#: CloudFormation poll that follows it so a fallback destroy never gets abandoned mid-flight.
_CLEANUP_DESTROY_BUDGET_S = 500.0
_CLEANUP_WAIT_BUDGET_S = 300.0
_TOOLKIT_WAIT_BUDGET_S = 90.0


def _cdk_destroy(
    ctx,
    app: dict,
    stack: str,
    *,
    destroy_timeout_s: float = _DESTROY_BUDGET_S,
    wait_timeout_s: float = 900.0,
) -> str:
    """`cdk destroy --force` the APP stack, verify through CloudFormation that it is gone, then
    purge its assets. A stack left behind raises.
    """
    rec = app["owned"].get(stack)
    if rec is None or rec.get("gone"):
        return f"{stack} already destroyed"
    asm = rec.get("asm")
    try:
        done = subprocess.run(
            ["cdk", "destroy", "--app", str(asm), stack, "--force", *_CDK_FLAGS],
            cwd=str(app["work"]),
            env=app["env"],
            capture_output=True,
            text=True,
            timeout=destroy_timeout_s,
        )
        rc, tail = done.returncode, _one_line(done.stderr or done.stdout, 200)
    except subprocess.TimeoutExpired as exc:
        # Deliberately not interpolating the exception text.
        msg = (
            f"cdk destroy for stack {stack} did not finish inside "
            f"{destroy_timeout_s:.0f}s of wall clock — every resource the stack owns remains in "
            "the account, and so does everything it published"
        )
        raise RuntimeError(msg) from exc
    except OSError as exc:
        msg = (
            f"cdk destroy for stack {stack} could not be launched "
            f"({type(exc).__name__}) — the stack remains in the account"
        )
        raise RuntimeError(msg) from exc
    final = _wait_stack_gone(ctx, stack, timeout_s=wait_timeout_s)
    if final is not None and final != "DELETE_COMPLETE":
        msg = (
            f"stack {stack} is {final} after cdk destroy (rc={rc}) — its resources remain "
            f"in the account: {tail}"
        )
        raise RuntimeError(msg)
    rec["gone"] = True
    _purge_assets(ctx, rec.get("assets") or {})
    return f"{stack} deleted (rc={rc})"


def _log_lines(ctx, log_group: str, *, needle: str, timeout_s: float, legs, what: str) -> list[str]:
    """The events in *log_group* containing *needle*, waited for; a STREAM must exist too."""
    logs = ctx.client("logs")

    def _probe():
        try:
            streams = logs.describe_log_streams(logGroupName=log_group, limit=5).get(
                "logStreams", []
            )
        except ClientError:
            return None
        if not streams:
            return None
        found = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{needle}"')
        return [e["message"] for e in found.get("events", [])] or None

    return _poll_until(
        _probe,
        lambda r: bool(r),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{what} in log group {log_group}",
        legs=legs,
    )


def _metric_sum(ctx, namespace: str, name: str, *, minutes: int = 20) -> float:
    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)
    stats = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=name,
        StartTime=now - timedelta(minutes=minutes),
        EndTime=now + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(float(p["Sum"]) for p in stats.get("Datapoints", []))


def _alarm_state(ctx, alarm: str) -> str:
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm]).get("MetricAlarms", [])
    assert alarms, f"alarm {alarm} does not exist"
    return alarms[0]["StateValue"]


def _assert_alarm_fires(ctx, legs, alarm: str, *, timeout_s: float) -> str:
    """INSUFFICIENT_DATA -> ALARM, read from the alarm history CloudWatch recorded, because the
    alarm may already have flipped before this leg runs; StateReasonData must be present too."""
    _poll_until(
        lambda: _alarm_state(ctx, alarm),
        lambda s: s == "ALARM",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"alarm {alarm} crossing INSUFFICIENT_DATA -> ALARM",
        legs=legs,
    )
    history = ctx.client("cloudwatch").describe_alarm_history(
        AlarmName=alarm, HistoryItemType="StateUpdate", MaxRecords=30
    )
    crossings = []
    for item in history.get("AlarmHistoryItems", []):
        try:
            data = json.loads(item.get("HistoryData") or "{}")
        except ValueError:
            continue
        old = ((data.get("oldState") or {}).get("stateValue")) or ""
        new = ((data.get("newState") or {}).get("stateValue")) or ""
        if new == "ALARM":
            crossings.append(f"{old}->{new}")
    assert crossings, f"alarm {alarm} reads ALARM but recorded no StateUpdate transition into it"
    assert any(c.startswith("INSUFFICIENT_DATA") for c in crossings), (
        f"alarm {alarm} never crossed INSUFFICIENT_DATA->ALARM; recorded {crossings}"
    )
    reason = ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]
    assert reason.get("StateReasonData"), f"alarm {alarm} is in ALARM with no StateReasonData"
    return f"{alarm} {crossings[0]} with datapoints recorded"


# --- the one environment prerequisite this flavor adds ----------------------


def _require_container_builder(ctx) -> None:
    """cdk-assets builds the IMAGE asset locally with a container builder; a missing one is a
    local prerequisite, so it is detected before any cdk call is attributed to the target."""
    require_tools("docker")


def _http_get(ctx, url: str, timeout_s: float = 10.0):
    """(status, body) for a plain GET. An HTTP error STATUS is returned rather than raised, so a
    503-from-the-load-balancer is an observation; a transport failure returns (None, reason)."""
    _url, _route = ctx.endpoint_route(url)
    request = urllib.request.Request(_url, headers={**({"User-Agent": "sim2real-xsvc"}), **_route})
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


# --- leg helpers -------------------------------------------------------------


def _image_asset(assets: dict[str, list[dict]]) -> dict:
    images = assets.get("images") or []
    assert len(images) == 1, f"expected one image asset, assembly declares {len(images)}"
    return images[0]


def _deployed_image(ctx, task_definition_arn: str) -> str:
    definition = ctx.client("ecs").describe_task_definition(taskDefinition=task_definition_arn)
    containers = definition["taskDefinition"]["containerDefinitions"]
    assert containers, "the deployed task definition declares no container"
    return containers[0]["image"]


def _assert_image_asset_published(ctx, dep: dict) -> str:
    """The image cdk-assets built is IN the bootstrap asset repository under the content hash the
    assembly declared, and the deployed task definition references that repository and tag."""
    image = _image_asset(dep["assets"])
    described = ctx.client("ecr").describe_images(
        repositoryName=image["repo"], imageIds=[{"imageTag": image["tag"]}]
    )["imageDetails"]
    assert described, f"no image tagged {image['tag']} in {image['repo']}"
    assert described[0]["imageSizeInBytes"] > 0, "the published image has no layers"

    referenced = _deployed_image(ctx, dep["outputs"]["TaskDefinitionArn"])
    assert image["repo"] in referenced, (
        f"the task definition runs {referenced}, which is not in the bootstrap asset repository "
        f"{image['repo']}"
    )
    assert image["tag"] in referenced or (described[0].get("imageDigest") or "?") in referenced, (
        f"the task definition runs {referenced}, which is neither the published tag {image['tag']} "
        "nor its digest"
    )
    template_asset = _template_asset(dep["assets"])
    ctx.client("s3").head_object(Bucket=template_asset["bucket"], Key=template_asset["key"])
    return (
        f"{image['repo']}:{image['tag'][:12]}… ({described[0]['imageSizeInBytes']}B) referenced by "
        f"{referenced.rsplit('/', 1)[-1][:40]}"
    )


def _assert_alb_serves_the_image(ctx, legs, dep: dict, *, greeting: str) -> str:
    """A real GET through the load balancer, answered by the process the published image runs."""
    outputs = dep["outputs"]
    url = f"http://{outputs['LoadBalancerDns']}/order"
    status, body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=600.0,
        interval_s=2.0,
        description=f"HTTP 200 through the load balancer at {url}",
        legs=legs,
    )
    payload = json.loads(body)
    assert payload["marker"] == outputs["SiteMarker"], (
        f"the body carries marker {payload['marker']!r}, this deployment's is "
        f"{outputs['SiteMarker']!r} — the response is not from this task definition"
    )
    assert payload["greeting"] == greeting, (
        f"the body carries greeting {payload['greeting']!r}, the deployed value is {greeting!r}"
    )
    health = ctx.client("elbv2").describe_target_health(
        TargetGroupArn=outputs["TargetGroupArn"]
    )["TargetHealthDescriptions"]
    states = [t["TargetHealth"]["State"] for t in health]
    assert "healthy" in states, f"the load balancer answered 200 with targets {states}"
    service = ctx.client("ecs").describe_services(
        cluster=outputs["ClusterName"], services=[outputs["ServiceName"]]
    )["services"][0]
    assert service["runningCount"] >= 1, f"service reports runningCount {service['runningCount']}"
    return f"{status} from {url}: greeting {greeting}, marker {payload['marker']}, targets {states}"


def _assert_container_log_stream(ctx, legs, dep: dict) -> str:
    """The awslogs driver carried the container's own structured line into the log group, on a
    stream the driver named for the task."""
    outputs = dep["outputs"]
    logs = ctx.client("logs")
    lines = _log_lines(
        ctx,
        outputs["LogGroupName"],
        needle="SIM2REAL_REQUEST",
        timeout_s=300.0,
        legs=legs,
        what="the container's structured request line",
    )
    records = [json.loads(line) for line in lines if line.strip().startswith("{")]
    assert records, f"no JSON line among {len(lines)} matching events"
    assert records[0]["marker"] == outputs["SiteMarker"], (
        f"the log line carries marker {records[0]['marker']!r}, not this deployment's"
    )
    streams = logs.describe_log_streams(logGroupName=outputs["LogGroupName"])["logStreams"]
    prefixed = [s["logStreamName"] for s in streams if s["logStreamName"].startswith(outputs["StreamPrefix"])]
    assert prefixed, (
        f"no stream under the awslogs prefix {outputs['StreamPrefix']!r}: "
        f"{_one_line([s['logStreamName'] for s in streams], 90)}"
    )
    return f"{len(lines)} line(s) on {prefixed[0]}"


def _assert_metric_datapoint(ctx, legs, dep: dict) -> str:
    namespace, name = dep["outputs"]["MetricNamespace"], dep["outputs"]["MetricName"]
    total = _poll_until(
        lambda: _metric_sum(ctx, namespace, name),
        lambda v: v >= 1.0,
        timeout_s=360.0,
        interval_s=2.0,
        description=f"metric-filter datapoint for {namespace}/{name}",
        legs=legs,
    )
    return f"{namespace}/{name} Sum={total}"


def _assert_alarms(ctx, legs, dep: dict) -> str:
    """The request alarm crosses INSUFFICIENT_DATA->ALARM; the unhealthy-host alarm is the control
    and must NOT, because the service is healthy."""
    fired = _assert_alarm_fires(
        ctx, legs, dep["outputs"]["RequestAlarmName"], timeout_s=480.0
    )
    control = _alarm_state(ctx, dep["outputs"]["UnhealthyAlarmName"])
    assert control == "OK", (
        f"the unhealthy-host control alarm is {control} while the load balancer is serving 200s — "
        "an alarm that fires regardless of its metric proves nothing about the one that did"
    )
    return f"{fired}; control alarm OK"


def _assert_broken_variant_denied(ctx, legs, app: dict, dep: dict, broken_stack: str, context: dict) -> str:
    """The same published image under an execution role with no ECR permission: registry auth is
    refused BY NAME, the task never starts, and no log stream is ever created."""
    outputs = dep["outputs"]
    image = _deployed_image(ctx, outputs["TaskDefinitionArn"])
    broken = _cdk_deploy_stack(
        ctx,
        legs,
        app,
        stack=broken_stack,
        asm=_cdk_synth(
            ctx, legs, app, asm_name="asmbroken", context=dict(context, image_uri=image)
        ),
        timeout_s=900.0,
    )
    ecs = ctx.client("ecs")
    started = ecs.run_task(
        cluster=outputs["ClusterName"],
        taskDefinition=broken["outputs"]["BrokenTaskDefinitionArn"],
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": outputs["Subnets"].split(","),
                "securityGroups": [outputs["SecurityGroupId"]],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert started.get("tasks"), f"RunTask started nothing: {_one_line(started.get('failures'), 100)}"
    task_arn = started["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.stop_task(cluster=outputs["ClusterName"], task=task_arn, reason="sim2real"),
            "InvalidParameterException",
        )
    )
    stopped = _poll_until(
        lambda: ecs.describe_tasks(cluster=outputs["ClusterName"], tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=420.0,
        interval_s=2.0,
        description="the unauthorized task reaching STOPPED",
        legs=legs,
    )
    reason = " ".join(
        [
            stopped.get("stoppedReason") or "",
            *[c.get("reason") or "" for c in stopped.get("containers") or []],
        ]
    )
    assert "not authorized" in reason, (
        f"the task stopped, but not on authorization: {_one_line(reason, 130)}"
    )
    assert "ecr:" in reason, (
        f"the denial does not name the action namespace that was withheld: {_one_line(reason, 130)}"
    )
    # NOT `runtimeId`: ECS assigns one at placement, before the registry-auth pull, so a denied task
    # still carries it. `TaskFailedToStart` is the stopCode for a task that never reached RUNNING.
    assert stopped.get("stopCode") == "TaskFailedToStart", (
        f"stopCode is {stopped.get('stopCode')!r}, not TaskFailedToStart — that means the task DID "
        f"start before stopping, so the registry-auth denial did not prevent it running: {_one_line(reason, 130)}"
    )
    assert "startedAt" not in stopped, (
        f"the task reports startedAt={stopped.get('startedAt')!r} despite the registry-auth denial — "
        "a task that never started has no start time"
    )

    # Effect-absent at the destination: the awslogs driver creates the stream when the container
    # starts, so a container that never started leaves the group empty. The wired service's group is
    # the control — it has streams, so an empty group is attributable to the task, not to logging.
    logs = ctx.client("logs")
    broken_streams = logs.describe_log_streams(
        logGroupName=broken["outputs"]["BrokenLogGroupName"]
    ).get("logStreams", [])
    assert not broken_streams, (
        "the task never started yet the log group holds streams: "
        f"{_one_line([s['logStreamName'] for s in broken_streams], 90)}"
    )
    control_streams = logs.describe_log_streams(logGroupName=outputs["LogGroupName"]).get(
        "logStreams", []
    )
    assert control_streams, "the control log group is empty too — the absence proves nothing"
    return f"ecr auth denied for {task_arn.rsplit('/', 1)[-1]}, no stream, control has {len(control_streams)}"


def _assert_env_change_modifies(ctx, legs, app: dict, dep: dict, context: dict) -> str:
    """A second deploy that changes ONE container environment value: a new task-definition revision
    the service is updated onto in place, and NO image push, because the image's content is the same.
    """
    ecs = ctx.client("ecs")
    outputs = dep["outputs"]
    before_service = ecs.describe_services(
        cluster=outputs["ClusterName"], services=[outputs["ServiceName"]]
    )["services"][0]
    before_revision = int(outputs["TaskDefinitionArn"].rsplit(":", 1)[-1])
    image = _image_asset(dep["assets"])
    pushed_before = ctx.client("ecr").describe_images(
        repositoryName=image["repo"], imageIds=[{"imageTag": image["tag"]}]
    )["imageDetails"][0]["imagePushedAt"]

    updated = dict(context, greeting="rewired")
    again = _deploy_cdk_bootstrapped(
        ctx, legs, app, stack=dep["stack"], asm_name="asm2", context=updated, timeout_s=1800.0
    )
    assert again["status"] == "UPDATE_COMPLETE", (
        f"the second deploy left the stack in {again['status']}, not UPDATE_COMPLETE"
    )
    after_service = ecs.describe_services(
        cluster=outputs["ClusterName"], services=[again["outputs"]["ServiceName"]]
    )["services"][0]
    assert after_service["serviceArn"] == before_service["serviceArn"], (
        "the service was REPLACED by a container environment change: "
        f"{before_service['serviceArn']} -> {after_service['serviceArn']}"
    )
    after_revision = int(again["outputs"]["TaskDefinitionArn"].rsplit(":", 1)[-1])
    assert after_revision == before_revision + 1, (
        f"task definition went from revision {before_revision} to {after_revision} — an environment "
        "change must register exactly one new revision"
    )
    assert after_service["taskDefinition"].endswith(f":{after_revision}"), (
        f"the service still runs {after_service['taskDefinition']} after the update"
    )

    after_image = _image_asset(again["assets"])
    assert after_image["tag"] == image["tag"], (
        f"the image tag moved from {image['tag'][:10]}… to {after_image['tag'][:10]}… without the "
        "image's content changing"
    )
    pushed_after = ctx.client("ecr").describe_images(
        repositoryName=image["repo"], imageIds=[{"imageTag": image["tag"]}]
    )["imageDetails"][0]["imagePushedAt"]
    assert pushed_after == pushed_before, (
        f"cdk-assets re-pushed an image whose content hash was unchanged ({pushed_before} -> "
        f"{pushed_after})"
    )

    dep["assets"] = again["assets"]
    dep["asm"] = again["asm"]
    dep["outputs"] = again["outputs"]
    context.update(updated)
    _assert_alb_serves_the_image(ctx, legs, dep, greeting="rewired")

    # A content change must move the image tag; asserted at the SYNTH boundary because the tag is
    # the content hash, and a third deploy would cost more wall clock than the rest of the workflow.
    server = app["work"] / "container" / "server.py"
    server.write_text(server.read_text().replace('BOOT_TOKEN = "SIM2REAL_BOOT"', 'BOOT_TOKEN = "SIM2REAL_BOOTED"'))
    rebuilt = _cdk_synth(ctx, legs, app, asm_name="asm3", context=context)
    rebuilt_image = _image_asset(_read_assets(rebuilt, dep["stack"], app["account"], ctx.region))
    assert rebuilt_image["tag"] != image["tag"], (
        "the image's content changed and its asset tag did not — cdk-assets would keep serving the "
        "image already in the repository"
    )
    return (
        f"service updated in place r{before_revision}->r{after_revision}, image not re-pushed, "
        f"content change moves the tag to {rebuilt_image['tag'][:10]}…"
    )


def _purge_task_definitions(ctx, *arns: str) -> str:
    """Hard-delete the INACTIVE revisions of the families *arns* belong to: a stack delete only
    deregisters a task definition, which would otherwise list as INACTIVE forever."""
    ecs = ctx.client("ecs")
    families = {arn.split("/", 1)[1].rsplit(":", 1)[0] for arn in arns if arn}
    purged = 0
    for family in families:
        revisions = [
            arn
            for page in ecs.get_paginator("list_task_definitions").paginate(
                familyPrefix=family, status="INACTIVE"
            )
            for arn in page.get("taskDefinitionArns") or []
        ]
        if revisions:
            ecs.delete_task_definitions(taskDefinitions=revisions)
            purged += len(revisions)
    return f"{purged} task definition revision(s) purged"


def _assert_destroy_stops_serving(ctx, legs, app: dict, dep: dict, broken_stack: str) -> str:
    """After destroy: the load balancer is gone AND stops answering, and the image this check pushed
    is out of the shared asset repository."""
    outputs = dep["outputs"]
    url = f"http://{outputs['LoadBalancerDns']}/order"
    images = list(dep["record"]["assets"]["images"])
    cfn = ctx.client("cloudformation")
    broken_task_arn = _stack_outputs(cfn, broken_stack).get("BrokenTaskDefinitionArn")
    # The two stacks share nothing, so they are destroyed side by side.
    broken_destroy = _start(lambda: _cdk_destroy(ctx, app, broken_stack))
    try:
        main_result = _cdk_destroy(ctx, app, dep["stack"])
    finally:
        # Joined even when the main destroy raises, so neither destroy outlives this leg.
        broken_result = broken_destroy()
    for stack in (broken_stack, dep["stack"]):
        status = _stack_status(cfn, stack)
        assert status in (None, "DELETE_COMPLETE"), f"stack {stack} is {status} after destroy"

    gone = _swallow(
        lambda: ctx.client("elbv2").describe_load_balancers(
            LoadBalancerArns=[outputs["LoadBalancerArn"]]
        ),
        "LoadBalancerNotFound",
    )
    assert gone is None, "the load balancer outlived its stack"
    absent = _swallow(
        lambda: ctx.client("ecs").describe_task_definition(
            taskDefinition=outputs["TaskDefinitionArn"]
        ),
        "ClientException",
    )
    assert absent is None or absent["taskDefinition"]["status"] != "ACTIVE", (
        "the task definition is still ACTIVE after the stack was deleted"
    )

    # Not just "the API says it is gone": the endpoint must stop answering. A 200 here would mean the
    # target kept serving a deleted deployment.
    status, body = _poll_until(
        lambda: _http_get(ctx, url, timeout_s=8.0),
        lambda r: r[0] != 200,
        timeout_s=300.0,
        interval_s=2.0,
        description=f"the load balancer at {url} stopping serving",
        legs=legs,
    )
    assert outputs["SiteMarker"] not in (body or ""), (
        "the deleted deployment is still answering with its marker"
    )

    surviving = []
    for image in images:
        try:
            described = ctx.client("ecr").describe_images(
                repositoryName=image["repo"], imageIds=[{"imageTag": image["tag"]}]
            )["imageDetails"]
            if described:
                surviving.append(f"{image['repo']}:{image['tag'][:10]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ImageNotFoundException", "RepositoryNotFoundException"):
                raise
            continue
    assert not surviving, (
        "teardown left pushed images in the SHARED bootstrap asset repository, which no name-prefix "
        f"cleanup matches and which is billed as storage: {_one_line(surviving, 90)}"
    )
    task_defs_purged = _purge_task_definitions(ctx, outputs["TaskDefinitionArn"], broken_task_arn)
    return (
        f"{broken_result}; {main_result}; {url} now {status}; {len(images)} image(s) purged; "
        f"{task_defs_purged}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
