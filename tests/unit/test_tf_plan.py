"""Terraform plan conversion for pre-change analysis."""

from __future__ import annotations

import json

import pytest

from nac_nd.exceptions import InputError
from nac_nd.tf_plan import (
    is_terraform_plan,
    prepare_prechange_content,
    terraform_plan_to_payload,
)

SAMPLE_PLAN = {
    "format_version": "1.2",
    "terraform_version": "1.14.0",
    "resource_changes": [
        {
            "type": "local_sensitive_file",
            "change": {"actions": ["create"], "after": {"filename": "x"}},
        },
        {
            "type": "aci_rest_managed",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {
                    "class_name": "fvTenant",
                    "dn": "uni/tn-TEST",
                    "content": {"name": "TEST", "descr": ""},
                },
            },
        },
        {
            "type": "aci_rest_managed",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {
                    "class_name": "fvAp",
                    "dn": "uni/tn-TEST/ap-APP",
                    "content": {"name": "APP", "descr": ""},
                },
            },
        },
    ],
}


def test_terraform_plan_json_is_detected() -> None:
    assert is_terraform_plan(SAMPLE_PLAN) is True
    assert is_terraform_plan({"imdata": []}) is False
    assert is_terraform_plan({"format_version": "1.2"}) is False


def test_non_terraform_json_is_left_unchanged() -> None:
    payload = b'{"imdata": [{"fvTenant": {"attributes": {"name": "X"}}}]}'

    assert prepare_prechange_content(payload) == payload


def test_non_json_is_left_unchanged() -> None:
    payload = b"not json"

    assert prepare_prechange_content(payload) == payload


def test_terraform_plan_is_converted_to_a_single_subtree() -> None:
    payload = terraform_plan_to_payload(SAMPLE_PLAN)
    parsed = json.loads(payload)

    assert "polUni" in parsed
    tenant = parsed["polUni"]["children"][0]["fvTenant"]
    assert tenant["attributes"]["name"] == "TEST"
    child_classes = {next(iter(child)) for child in tenant["children"]}
    assert child_classes == {"fvAp"}


def test_prepare_prechange_content_converts_terraform_plan_bytes() -> None:
    raw = json.dumps(SAMPLE_PLAN).encode()

    converted = prepare_prechange_content(raw)

    assert b'"fvTenant"' in converted
    assert b"planned_values" not in converted


def test_delete_actions_mark_objects_as_deleted() -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "type": "aci_rest_managed",
                "change": {
                    "actions": ["delete"],
                    "before": {
                        "class_name": "fvTenant",
                        "dn": "uni/tn-OLD",
                        "content": {"name": "OLD"},
                    },
                    "after": None,
                },
            }
        ],
    }

    payload = terraform_plan_to_payload(plan)

    assert b'"status": "deleted"' in payload
    assert b"uni/tn-OLD" in payload


def test_an_empty_terraform_plan_is_bad_input() -> None:
    plan = {"format_version": "1.2", "resource_changes": []}

    with pytest.raises(InputError, match="no aci_rest_managed"):
        terraform_plan_to_payload(plan)
