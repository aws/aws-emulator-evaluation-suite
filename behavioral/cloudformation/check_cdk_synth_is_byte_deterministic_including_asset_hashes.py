"""cdk-synth-is-byte-deterministic-including-asset-hashes."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-synth-is-byte-deterministic-including-asset-hashes"
GROUP = "deploy"
SERVICES = ["cloudformation"]

# Per-command caps are deliberately generous; the sum of what this check actually waits must stay
# under 1800s.
_SYNTH_TIMEOUT_S = 240.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 300.0

_INLINE_APP = "cdk_fn_inline"
_ASSET_APP = "cdk_fn_asset"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """`cdk synth` is byte-deterministic, asset ids included; one changed handler byte moves only the
    asset-id-bearing fields; and the synthesised template deploys a function whose invoke returns
    this run's marker."""
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    stack = ctx.unique_name("sim2real-cdkdet-")
    marker = ctx.unique_name("marker-")
    base_context = {"account": account, "region": ctx.region, "stack_name": stack}

    inline_app = _stage_app(ctx, _INLINE_APP)
    asset_app = _stage_app(ctx, _ASSET_APP)

    try:
        # ---- 1. asset-free determinism: byte-identical, nothing excluded -----------------------
        first = _synth(ctx, inline_app, stack, {**base_context, "marker": marker}, out="out-1")
        second = _synth(ctx, inline_app, stack, {**base_context, "marker": marker}, out="out-2")
        assert first == second, (
            f"two `cdk synth` runs of {_INLINE_APP!r} with identical context produced DIFFERENT "
            f"template bytes: {len(first)} vs {len(second)} bytes; first differing offset "
            f"{_first_difference(first, second)!r}"
        )
        # Guard against the degenerate way this could pass: an empty or trivial template.
        doc = json.loads(first)
        fn_ids = [k for k, v in doc["Resources"].items() if v["Type"] == "AWS::Lambda::Function"]
        assert len(fn_ids) == 1, (
            f"the synthesised template holds {len(fn_ids)} AWS::Lambda::Function resources "
            f"({fn_ids!r}), expected exactly 1 — the byte-identity above would otherwise be a "
            f"statement about an empty template"
        )
        assert "/cdk-bootstrap/" not in first.decode(), (
            "the asset-free app's template references /cdk-bootstrap/, so LegacyStackSynthesizer "
            "did not keep this app off the bootstrap path; template head: "
            f"{first.decode()[:300]!r}"
        )

        # ---- 2. asset-bearing determinism across an mtime change ------------------------------
        handler = asset_app / "handler" / "index.py"
        original_source = handler.read_bytes()
        asset_first = _synth(ctx, asset_app, stack, base_context, out="out-1")
        # Rewrite identical bytes: same content, new mtime. Any timestamp folded into the asset id
        # shows up as a template difference here.
        handler.write_bytes(original_source)
        asset_second = _synth(ctx, asset_app, stack, base_context, out="out-2")
        assert asset_first == asset_second, (
            f"the asset-bearing app's template changed after its source file's mtime moved with "
            f"identical CONTENT: {len(asset_first)} vs {len(asset_second)} bytes; first differing "
            f"offset {_first_difference(asset_first, asset_second)!r} — the asset id is not a pure "
            f"content hash"
        )
        hash_before = _asset_id(asset_app / "out-1", stack)

        # ---- 3. one changed byte moves the id, and moves nothing else -------------------------
        handler.write_bytes(original_source.replace(b'"variant": "a"', b'"variant": "b"'))
        assert handler.read_bytes() != original_source, (
            "the determinism check failed to mutate its own handler source — the marker string "
            f"'\"variant\": \"a\"' was not present in {handler}"
        )
        asset_third = _synth(ctx, asset_app, stack, base_context, out="out-3")
        hash_after = _asset_id(asset_app / "out-3", stack)
        assert hash_after != hash_before, (
            f"one changed byte of handler source left the asset id at {hash_before!r} — the id is "
            f"not derived from content"
        )
        changed = _differing_leaves(json.loads(asset_first), json.loads(asset_third))
        assert changed, (
            f"the asset id moved from {hash_before!r} to {hash_after!r} but no leaf of the template "
            f"changed — the template does not reference the asset it publishes"
        )
        code_key_paths = [p for p in changed if p.endswith("Properties.Code.S3Key")]
        assert len(code_key_paths) == 1, (
            f"expected exactly one differing leaf at Properties.Code.S3Key, the differing leaves "
            f"were {sorted(changed)!r}"
        )
        unexplained = {
            path: pair for path, pair in changed.items()
            if not (hash_before in str(pair[0]) and hash_after in str(pair[1]))
        }
        assert not unexplained, (
            f"the source change altered template leaves that do NOT carry the asset id: "
            f"{ {k: v for k, v in list(unexplained.items())[:4]} !r}; expected every difference to "
            f"be old id {hash_before!r} -> new id {hash_after!r}"
        )

        # ---- 4. TERMINAL READ: the byte-identical template deploys, and its code runs ---------
        _cdk(ctx, inline_app, ["deploy", stack, "--require-approval", "never",
                               "--outputs-file", "out.json"],
             {**base_context, "marker": marker}, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

        outputs = json.loads((inline_app / "out.json").read_text())[stack]
        fn_name = outputs["FunctionName"]
        # Independent read, different operation from `cdk deploy`: ask Lambda, not CloudFormation.
        payload = _invoke(lam, fn_name, {"items": [1, 2, 3]})
        assert payload == {"marker": marker, "n": 3}, (
            f"invoking the deployed function {fn_name!r} returned {payload!r}, expected "
            f"{{'marker': {marker!r}, 'n': 3}} — the byte-stable template did not deploy the code "
            f"this run synthesised"
        )
        described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        assert described["StackStatus"] == "CREATE_COMPLETE", (
            f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE after a "
            f"`cdk deploy` that exited 0"
        )
    finally:
        # Verified inline teardown. `ctx.on_cleanup` runs on a thread joined with a 60s cap, and a
        # CFN stack delete plus its confirming read does not reliably fit in 60s — a cut-off
        # teardown PASSES the check while leaking the whole stack. The registration above stays as
        # the failure-path net only.
        _teardown(ctx, stack)


# ===== helpers =====


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo.

    A missing app directory fails the check rather than being created.
    """
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*. `--no-version-reporting` drops the `AWS::CDK::Metadata` resource
    and CLI telemetry; `--no-color` keeps ANSI escapes out of asserted output."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
            f"{output[-1200:]!r}"
        )
    return result.returncode, output


def _synth(ctx, work: Path, stack: str, context: dict[str, str], *, out: str) -> bytes:
    """Synthesise into `<work>/<out>` and return the template's exact bytes."""
    shutil.rmtree(work / out, ignore_errors=True)
    _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
         timeout_s=_SYNTH_TIMEOUT_S, expect_rc=0)
    template = work / out / f"{stack}.template.json"
    assert template.is_file(), (
        f"`cdk synth` exited 0 but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return template.read_bytes()


def _asset_id(assembly: Path, stack: str) -> str:
    """The single file-asset id in this assembly that is NOT the stack template itself."""
    manifest = json.loads((assembly / f"{stack}.assets.json").read_text())
    files = manifest["files"]
    ids = [k for k, v in files.items()
           if v.get("source", {}).get("path") != f"{stack}.template.json"]
    assert len(ids) == 1, (
        f"expected exactly one non-template file asset in {assembly}, the manifest listed "
        f"{ {k: v.get('source', {}).get('path') for k, v in files.items()} !r}"
    )
    return ids[0]


def _flatten(doc: Any, prefix: str = "") -> dict[str, Any]:
    """Every scalar leaf of a JSON document, keyed by dotted path."""
    if isinstance(doc, dict):
        out: dict[str, Any] = {}
        for key, value in doc.items():
            out.update(_flatten(value, f"{prefix}.{key}" if prefix else str(key)))
        return out
    if isinstance(doc, list):
        out = {}
        for index, value in enumerate(doc):
            out.update(_flatten(value, f"{prefix}[{index}]"))
        return out
    return {prefix: doc}


def _differing_leaves(left: Any, right: Any) -> dict[str, tuple[Any, Any]]:
    """Paths whose leaf value differs between two documents, with both values."""
    flat_left, flat_right = _flatten(left), _flatten(right)
    paths = set(flat_left) | set(flat_right)
    sentinel = object()
    return {
        path: (flat_left.get(path, sentinel), flat_right.get(path, sentinel))
        for path in paths
        if flat_left.get(path, sentinel) != flat_right.get(path, sentinel)
    }


def _first_difference(left: bytes, right: bytes) -> str:
    """A short, quotable description of where two byte strings first diverge."""
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return f"offset {index}: {left[max(0, index - 40):index + 40]!r} vs " \
                   f"{right[max(0, index - 40):index + 40]!r}"
    return f"identical for {min(len(left), len(right))} bytes, then lengths diverge"


def _invoke(lam, fn_name: str, event: dict[str, Any]) -> Any:
    """Invoke and decode, treating a handler error as a failure rather than a payload."""
    response = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
    body = response["Payload"].read()
    assert "FunctionError" not in response, (
        f"invoking {fn_name!r} raised {response.get('FunctionError')!r}: {body[:400]!r}"
    )
    return json.loads(body)


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    """Delete, then poll to DELETE_COMPLETE. Raises on timeout so a leak is never silent."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in str(exc):
                raise
            return
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        # Bounded: CloudFormation deletes are asynchronous and there is no notification channel.
        time.sleep(2)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _teardown(ctx, stack: str) -> None:
    """Delete the stack and CONFIRM it is gone, inside this check's own declared budget."""
    found = sys.exc_info()[1]
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    try:
        _delete_stack_and_wait(ctx, stack, timeout_s=max(30.0, deadline - time.monotonic()))
    except Exception as exc:
        if found is None:
            raise
        raise AssertionError(f"{found!r}; teardown failed: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
