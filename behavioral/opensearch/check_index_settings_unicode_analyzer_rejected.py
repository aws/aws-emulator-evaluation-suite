"""index-settings-unicode-analyzer-rejected."""
from __future__ import annotations

import random
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "index-settings-unicode-analyzer-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]

_ANALYZER_NAME = "自定义分析器_ünïcödé_анализатор"
#: The same schema with an ASCII analyzer name. The control, so the refusal of the unicode name is
#: attributable to the NAME and not to the domain's index-management surface being unusable.
_ASCII_ANALYZER_NAME = "s2r_custom_analyzer"
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A NON-ASCII custom-analyzer name in IndexSchema is refused by CreateIndex with a sustained
    DependencyFailureException, not a ValidationException, while the byte-identical schema with an
    ASCII analyzer name on the same domain, moments earlier, is CREATED and round-trips.
    """
    opensearch = ctx.client("opensearch")
    domain_name = _create_active_domain(ctx)

    # ---- control: ASCII analyzer name, same schema shape ----
    control_index = _index_name(ctx)
    control_status = _retry_dependency_failure(
        lambda: opensearch.create_index(
            DomainName=domain_name,
            IndexName=control_index,
            IndexSchema=_analyzer_schema(_ASCII_ANALYZER_NAME),
        )
    )["Status"]
    assert control_status == "CREATED", (
        f"control (ASCII analyzer name) CreateIndex did not return CREATED, got {control_status!r} "
        "-- the domain's index-management surface is not usable, so the unicode arm proves nothing"
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: opensearch.delete_index(DomainName=domain_name, IndexName=control_index)
        )
    )

    control_got = opensearch.get_index(DomainName=domain_name, IndexName=control_index)["IndexSchema"]
    control_analyzers = _dig(control_got, control_index, ["settings", "index", "analysis", "analyzer"]) or {}
    assert _ASCII_ANALYZER_NAME in control_analyzers, (
        f"control analyzer name lost on GetIndex: {control_got!r}"
    )
    control_title = _dig(control_got, control_index, ["mappings", "properties", "title", "analyzer"])
    assert control_title == _ASCII_ANALYZER_NAME, (
        f"expected the control title field analyzer {_ASCII_ANALYZER_NAME!r}, got {control_title!r}"
    )

    # MAPPINGS ONLY on UpdateIndex: index settings are fixed at creation and UpdateIndex refuses a
    # settings block outright with ValidationException ("Updates to index settings is not
    # supported"). The analyzer is already installed by CreateIndex; the new field only references
    # it by name.
    update_schema = {
        "mappings": {
            "properties": {
                "title": {"type": "text", "analyzer": _ASCII_ANALYZER_NAME},
                "body": {"type": "text", "analyzer": _ASCII_ANALYZER_NAME},
            }
        }
    }
    update_status = _retry_dependency_failure(
        lambda: opensearch.update_index(
            DomainName=domain_name, IndexName=control_index, IndexSchema=update_schema
        )
    )["Status"]
    assert update_status == "UPDATED", f"expected UpdateIndex Status UPDATED, got {update_status!r}"

    updated = opensearch.get_index(DomainName=domain_name, IndexName=control_index)["IndexSchema"]
    for field in ("title", "body"):
        got_analyzer = _dig(updated, control_index, ["mappings", "properties", field, "analyzer"])
        assert got_analyzer == _ASCII_ANALYZER_NAME, (
            f"expected the {field} field analyzer {_ASCII_ANALYZER_NAME!r} after UpdateIndex, got "
            f"{got_analyzer!r}"
        )

    # ---- the rejection: identical schema, non-ASCII analyzer name ----
    unicode_index = _index_name(ctx)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: opensearch.delete_index(DomainName=domain_name, IndexName=unicode_index)
        )
    )
    code, message = _sustained_error_code(
        lambda: opensearch.create_index(
            DomainName=domain_name,
            IndexName=unicode_index,
            IndexSchema=_analyzer_schema(_ANALYZER_NAME),
        )
    )
    assert code == "DependencyFailureException", (
        f"expected a non-ASCII custom-analyzer name to be refused with DependencyFailureException, "
        f"got {code!r}"
    )
    assert message == "The domain is not available now, please try again later.", (
        f"DependencyFailureException message {message!r}"
    )

    # Effect absent: the refused CreateIndex left no index behind.
    absent_code, absent_message = _error_code(
        lambda: opensearch.get_index(DomainName=domain_name, IndexName=unicode_index)
    )
    assert absent_code == "ResourceNotFoundException", (
        f"the refused unicode CreateIndex must have created nothing, got {absent_code!r}"
    )
    assert absent_message == f"Resource index {unicode_index} does not exist", (
        f"GetIndex not-found message {absent_message!r}"
    )

    # ---- the control index's teardown is asserted too, not merely performed ----
    delete_status = opensearch.delete_index(DomainName=domain_name, IndexName=control_index)["Status"]
    assert delete_status == "DELETED", f"expected DeleteIndex Status DELETED, got {delete_status!r}"

    not_found_code, not_found_message = _error_code(
        lambda: opensearch.get_index(DomainName=domain_name, IndexName=control_index)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"a deleted index must not be independently readable, got {not_found_code!r}"
    )
    gone = f"Resource index {control_index} does not exist"
    assert not_found_message == gone, f"GetIndex not-found message {not_found_message!r}"

    mutation_code, mutation_message = _error_code(
        lambda: opensearch.update_index(
            DomainName=domain_name, IndexName=control_index, IndexSchema=update_schema
        )
    )
    assert mutation_code == "ResourceNotFoundException", (
        f"UpdateIndex against a deleted index must be refused, got {mutation_code!r}"
    )
    assert mutation_message == gone, f"UpdateIndex not-found message {mutation_message!r}"

    recreated_status = _retry_dependency_failure(
        lambda: opensearch.create_index(
            DomainName=domain_name,
            IndexName=control_index,
            IndexSchema=_analyzer_schema(_ASCII_ANALYZER_NAME),
        )
    )["Status"]
    assert recreated_status == "CREATED", (
        f"a deleted index name must be reusable, got {recreated_status!r}"
    )


# ===== helpers =====


def _dig(schema, index_name: str, path: list):
    """Read *path* out of a GetIndex IndexSchema, tolerating the index-name wrapper.

    GetIndex echoes the schema NESTED under the index name -- on AWS a flat read of ``["settings"]``
    raises KeyError. IndexSchema is a Smithy ``document`` with no fixed shape, so both spellings are
    accepted here rather than hard-coding one shape. Returns None when the path is absent, so the
    caller's assertion reports it instead of raising KeyError.
    """
    for root in (schema.get(index_name) if isinstance(schema, dict) else None, schema):
        node = root
        for key in path:
            if not isinstance(node, dict) or key not in node:
                node = None
                break
            node = node[key]
        if node is not None:
            return node
    return None


def _analyzer_schema(analyzer_name: str) -> dict:
    """One custom analyzer, referenced by one text field. Only the analyzer NAME varies."""
    return {
        "settings": {
            "index": {
                "analysis": {"analyzer": {analyzer_name: {"type": "custom", "tokenizer": "standard"}}}
            }
        },
        "mappings": {"properties": {"title": {"type": "text", "analyzer": analyzer_name}}},
    }


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-").lower()
    cleaned = re.sub(r"[^a-z0-9-]", "-", raw)
    truncated = cleaned[:28].rstrip("-")
    if len(truncated) < 3:
        truncated = (truncated + "dom")[:28]
    return truncated


def _index_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-idx-").lower()
    cleaned = re.sub(r"[^a-z0-9-]", "-", raw)
    truncated = cleaned[:255].rstrip("-")
    if len(truncated) < 3:
        truncated = (truncated + "idx")[:255]
    return truncated


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the botocore Error (code, message). Raises if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _sustained_error_code(fn, attempts: int = 15, interval_s: float = 20.0) -> tuple[str, str]:
    """The error (code, message) fn raises on EVERY one of *attempts* tries, over ``attempts*interval_s``.

    A single DependencyFailureException would be ambiguous -- the same code is what a
    still-warming domain answers -- so the assertion is that the refusal is SUSTAINED, and the
    control above has already shown the surface working on this domain. An unexpected SUCCESS
    raises: a target ACCEPTING a call real AWS refuses is the strongest divergence signal there
    is, and must not pass as a code mismatch. A DIFFERENT code on a later attempt is
    returned as-is, so the caller's assertion reports it.
    """
    first: tuple[str, str] | None = None
    for attempt in range(attempts):
        try:
            result = fn()
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if first is None:
                first = code, err.response["Error"]["Message"]
            elif code != first[0]:
                return code, err.response["Error"]["Message"]
        else:
            raise AssertionError(
                f"real AWS refuses this call, but attempt {attempt} SUCCEEDED with {result!r}"
            )
        if attempt < attempts - 1:
            time.sleep(interval_s)
    assert first is not None
    return first


def _retry_dependency_failure(fn, attempts: int = 30, interval_s: float = 20.0):
    """Bounded retry (10 min ceiling) for DependencyFailureException/ThrottlingException.

    Observed on real AWS: a domain that already reports Processing=False with a published
    Endpoint can still answer CreateIndex with DependencyFailureException ("the domain is not
    available now") for a while afterward -- describe_domain's readiness signal precedes the
    automatic-semantic-enrichment index API's own readiness -- so the bound is generous rather
    than tight. This wraps the ACCEPTED calls only; the refused one is _sustained_error_code.
    """
    last_err = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code in ("DependencyFailureException", "ThrottlingException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"index operation kept failing with a transient error: {last_err}")


def _create_active_domain(ctx, timeout_s: float = 2400.0, interval_s: float = 30.0) -> str:
    """Create a minimal single-node domain and poll until it leaves 'Processing'.

    AWS docs note domain creation typically takes 15-30 minutes; this uses a generous
    bounded poll rather than a fixed sleep.
    """
    opensearch = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    # Registered before the create call so a failure between create and registration can never
    # leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: opensearch.delete_domain(DomainName=domain_name)))

    kwargs = dict(
        DomainName=domain_name,
        # CreateIndex/UpdateIndex/GetIndex are gated behind automatic semantic enrichment,
        # which real AWS requires OpenSearch 2.19+ for -- 2.11 is rejected outright.
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        # Tagged at creation so a tag search can find it if cleanup is ever interrupted.
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    # CreateDomain is aggressively rate limited per account: back off on throttling.
    for attempt in range(12):
        try:
            opensearch.create_domain(**kwargs)
            break
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("CreateDomain still throttled after 12 attempts")

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status.get("Processing", True) and status.get("Endpoint") is not None:
            return domain_name
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
