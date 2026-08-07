"""Convert Terraform plan JSON into Nexus Dashboard pre-change payloads.

Terraform JSON plans from `terraform show -json plan.tfplan` are converted
into the APIC managed-object subtree Nexus Dashboard expects. Conversion
follows the same rules as nexus-pcv's `load_tf_plan`.
"""

from __future__ import annotations

import json
import re
from typing import Any

from nac_nd.apic import ApicObject
from nac_nd.exceptions import InputError
from nac_nd.rn_mappings import RN_PREFIX_CLASSNAME_MAPPINGS

_ACTIONS = frozenset({"create", "update", "delete"})


def is_terraform_plan(data: Any) -> bool:
    """Return whether `data` looks like `terraform show -json` output."""
    return (
        isinstance(data, dict)
        and "resource_changes" in data
        and "format_version" in data
    )


def prepare_prechange_content(content: bytes) -> bytes:
    """Normalise a candidate configuration file for ND upload.

    Terraform plan JSON is converted to an APIC MO subtree. Other JSON and
    non-JSON payloads are returned unchanged.
    """
    stripped = content.strip()
    if not stripped:
        return content
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return content
    if not is_terraform_plan(parsed):
        return content
    return terraform_plan_to_payload(parsed)


def terraform_plan_to_payload(tf_plan: dict[str, Any]) -> bytes:
    """Build the MO subtree JSON bytes ND accepts from a Terraform plan."""
    root = _build_tf_plan_tree(tf_plan)
    if not root.children:
        raise InputError(
            "Terraform plan contains no aci_rest_managed create, update or "
            "delete changes."
        )
    return str(root.children[0]).encode()


def _build_tf_plan_tree(tf_plan: dict[str, Any]) -> ApicObject:
    root = ApicObject("root", {}, [], None)
    for change in tf_plan.get("resource_changes", []):
        if change.get("type") != "aci_rest_managed":
            continue
        actions = change.get("change", {}).get("actions", [])
        if not any(action in _ACTIONS for action in actions):
            continue
        if "delete" in actions:
            section = change["change"].get("before") or {}
            attributes = dict(section.get("content") or {})
            attributes["status"] = "deleted"
            attributes["dn"] = section.get("dn")
            classname = section.get("class_name")
        else:
            section = change["change"].get("after") or {}
            attributes = dict(section.get("content") or {})
            attributes["dn"] = section.get("dn")
            classname = section.get("class_name")
        attributes = {
            key: value
            for key, value in attributes.items()
            if value != "" and value is not None
        }
        root.insert(ApicObject(classname, attributes, [], None))
    _resolve_static_classnames(root)
    _resolve_tf_classnames(root, tf_plan)
    _check_classes(root)
    return root


def _resolve_static_classnames(root: ApicObject) -> None:
    dn = str(root["dn"])
    parts = dn.split("/")[-1].split("-", 1)
    prefix = parts[0]
    name = parts[1] if len(parts) > 1 else None
    if prefix in RN_PREFIX_CLASSNAME_MAPPINGS:
        mapping = RN_PREFIX_CLASSNAME_MAPPINGS[prefix]
        if root.cl is None:
            root.cl = mapping.get("class")
        if root.cl == mapping.get("class"):
            for key in mapping.get("keys", []):
                key_attribute = key.get("attribute")
                key_regex = key.get("regex")
                if (
                    key_attribute is not None
                    and key_regex is not None
                    and name is not None
                ):
                    match = re.search(key_regex, name)
                    if match is not None and key_attribute not in root.attributes:
                        root.attributes[key_attribute] = match.group()
    for child in root.children:
        _resolve_static_classnames(child)


def _resolve_tf_classnames(root: ApicObject, tf_plan: dict[str, Any]) -> None:
    if root.cl is None:
        dn = root["dn"]
        for change in tf_plan.get("resource_changes", []):
            change_body = change.get("change", {})
            section_name = "after" if change_body.get("after") is not None else "before"
            section = change_body.get(section_name) or {}
            if dn == section.get("dn"):
                root.cl = section.get("class_name")
                name = (section.get("content") or {}).get("name")
                if name:
                    root.attributes["name"] = name
                break
    for child in root.children:
        _resolve_tf_classnames(child, tf_plan)


def _check_classes(root: ApicObject) -> None:
    if root.cl is None:
        raise InputError(f"Missing classname for '{root['dn']}'")
    for child in root.children:
        _check_classes(child)
