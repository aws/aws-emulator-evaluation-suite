"""type-configuration-nested-json-structure-preserved."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "type-configuration-nested-json-structure-preserved"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A schema-derived TypeConfiguration round-trips with its nested structure intact, while
    every non-ASCII codepoint in a string value comes back as a literal "?", one-for-one.
    """
    cfn = ctx.client("cloudformation")
    role_arn = _create_execution_role(ctx)
    candidates = _activate_candidate_types(ctx, role_arn, max_candidates=8)
    if not candidates:
        raise AssertionError(
            "no publicly-activatable THIRD_PARTY resource type exposing a "
            "ConfigurationSchema was found in this account/Region within the search "
            "budget; testing configuration-payload fidelity needs a real, settable "
            "extension configuration, and the public registry search turned up nothing "
            "usable this run."
        )

    marker = "sim2real-\u00fcnicode-\u4e2d\u6587-\u0645\u0631\u062d\u0628\u0627"
    chosen = None
    _errs = []
    for type_name, schema in candidates:
        fill = _fill_from_schema(schema, marker)
        try:
            cfn.set_type_configuration(
                Type="RESOURCE",
                TypeName=type_name,
                ConfigurationAlias="Unicode",
                Configuration=json.dumps(fill, ensure_ascii=False),
            )
        except Exception as exc:
            _errs.append(f"{type_name}: {exc!r}")
            continue
        chosen = (type_name, fill)
        break

    if chosen is None:
        raise AssertionError(
            "every activated candidate extension rejected a schema-derived unicode "
            "configuration payload; none could be used to test payload fidelity this run: "
            + " ||| ".join(_errs)
        )

    type_name, fill = chosen
    type_arn = cfn.describe_type(Type="RESOURCE", TypeName=type_name)["Arn"]

    resp = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[{"TypeArn": type_arn, "TypeConfigurationAlias": "Unicode"}]
    )
    assert not resp.get("Errors"), f"expected no per-item errors, got {resp.get('Errors')!r}"
    configs = resp["TypeConfigurations"]
    assert len(configs) == 1, f"expected exactly 1 TypeConfiguration for {type_arn}, got {configs!r}"
    raw_configuration = configs[0]["Configuration"]
    round_tripped = json.loads(raw_configuration)

    expected = _mangle_non_ascii(fill)
    assert expected != fill, (
        f"fill {fill!r} contained no non-ASCII code point, so this run never exercised the "
        "ASCII-coercion contract the check targets"
    )
    assert round_tripped == expected, (
        f"type={type_name} sent={fill!r} expected(ASCII-mangled)={expected!r} "
        f"got={round_tripped!r} raw={raw_configuration!r}"
    )
    mangled_marker = _mangle_non_ascii(marker)
    assert mangled_marker in raw_configuration, (
        f"expected the marker's ASCII-mangled form {mangled_marker!r} in {raw_configuration!r}"
    )


def _mangle_non_ascii(value):
    """CloudFormation's round-trip rule: each non-ASCII codepoint becomes "?", all else untouched."""
    if isinstance(value, str):
        return value.encode("ascii", errors="replace").decode("ascii")
    if isinstance(value, dict):
        return {key: _mangle_non_ascii(v) for key, v in value.items()}
    if isinstance(value, list):
        return [_mangle_non_ascii(v) for v in value]
    return value


def _fill_from_schema(schema, marker, definitions=None, _depth=0):
    """Best-effort value conforming to a JSON-schema dict, resolving "#/definitions/X" $refs.

    Registry extensions declare nested structure via $refs; `_depth` caps self-referential cycles.
    """
    if definitions is None:
        definitions = schema.get("definitions") or {} if isinstance(schema, dict) else {}
    if not isinstance(schema, dict):
        return f"{marker}"
    if _depth > 8:
        return f"{marker}"
    if "$ref" in schema:
        target = definitions.get(schema["$ref"].rsplit("/", 1)[-1])
        if target is None:
            return f"{marker}"
        return _fill_from_schema(target, marker, definitions, _depth + 1)
    if schema.get("enum"):
        return schema["enum"][0]
    schema_type = schema.get("type")
    if schema_type == "object" or (schema_type is None and "properties" in schema):
        props = schema.get("properties") or {}
        return {key: _fill_from_schema(sub, marker, definitions, _depth + 1) for key, sub in props.items()}
    if schema_type == "array":
        items = schema.get("items")
        item_schema = items if isinstance(items, dict) else {}
        return [_fill_from_schema(item_schema, marker, definitions, _depth + 1)]
    if schema_type == "boolean":
        return True
    if schema_type in ("integer", "number"):
        minimum = schema.get("minimum")
        return minimum if isinstance(minimum, (int, float)) else 1
    return f"{marker}"


def _create_execution_role(ctx) -> str:
    """A trust-only role CloudFormation can assume as a third-party extension's ExecutionRoleArn.

    ActivateType requires one for PUBLIC THIRD_PARTY types; the configuration calls never invoke
    the handler, so the role needs no permissions.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfnext-exec-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _activate_candidate_types(ctx, role_arn, max_candidates=8, *, search_budget_s=150.0):
    """Activate up to `max_candidates` public THIRD_PARTY types exposing a ConfigurationSchema.

    Bounded by wall clock: ListTypes with a Category filter returns far fewer than MaxResults per
    page, so a page cap can stop before reaching any schema-bearing type.
    """
    cfn = ctx.client("cloudformation")
    out = []
    token = None
    deadline = time.monotonic() + search_budget_s
    while time.monotonic() < deadline and len(out) < max_candidates:
        kwargs = {
            "Visibility": "PUBLIC",
            "Type": "RESOURCE",
            "Filters": {"Category": "THIRD_PARTY"},
            "MaxResults": 20,
        }
        if token:
            kwargs["NextToken"] = token
        try:
            resp = cfn.list_types(**kwargs)
        except Exception:
            break
        for summary in resp.get("TypeSummaries", []):
            arn = summary.get("TypeArn")
            if not arn:
                continue
            try:
                described = cfn.describe_type(Arn=arn)
            except Exception:
                continue
            schema_raw = described.get("ConfigurationSchema")
            if not schema_raw:
                continue
            try:
                schema = json.loads(schema_raw)
            except (ValueError, TypeError):
                continue
            type_name = described.get("TypeName")
            if not type_name:
                continue
            # A per-run TypeNameAlias gives this run its own private copy of the public type,
            # so its configurations and deactivation never touch another run's activation.
            alias = f"Sim2Real::Cfg{uuid.uuid4().hex[:12]}::Type"
            if not _activate_with_retry(cfn, arn, alias, role_arn):
                continue
            ctx.on_cleanup(lambda tn=alias: cfn.deactivate_type(TypeName=tn, Type="RESOURCE"))
            out.append((alias, schema))
            if len(out) >= max_candidates:
                break
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _activate_with_retry(cfn, public_type_arn, alias, role_arn, *, timeout_s=12.0, interval_s=3.0):
    """ActivateType with a bounded retry: a new IAM role is not immediately assumable (eventual
    consistency). Returns False once the deadline passes so the candidate is skipped.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.activate_type(
                PublicTypeArn=public_type_arn, TypeNameAlias=alias, AutoUpdate=False, ExecutionRoleArn=role_arn
            )
            return True
        except Exception:
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
