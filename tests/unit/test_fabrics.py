"""Fabric inventory and fabric validation."""

from __future__ import annotations

import pytest

from nac_nd.client import fabric_name, is_aci_fabric
from nac_nd.exceptions import InputError
from tests.conftest import Lab, json_response

# Shaped as /api/v1/manage/fabrics responds: the identifier is `name`, `meta`
# is flat rather than nested under `counts`, and records carry no id.
INVENTORY = {
    "fabrics": [
        {"name": "FABRIC-A", "management": {"type": "aci"}, "category": "aci"},
        {"name": "FABRIC-B", "management": {"type": "aci"}, "category": "aci"},
        {"name": "NXOS-1", "management": {"type": "nxos"}, "category": "nxos"},
    ],
    "meta": {"total": 3, "remaining": 0},
}


def test_fabric_identifier_field_is_name_not_fabric_name() -> None:
    """/manage/fabrics spells this field `name`; other endpoints use
    `fabricName`."""
    assert fabric_name({"name": "FABRIC-A"}) == "FABRIC-A"
    assert fabric_name({"fabricName": "FABRIC-A"}) == ""


def test_flat_meta_is_not_read_through_the_nested_helper(make_client) -> None:
    """`meta` here is `{total, remaining}`, not `meta.counts`."""
    client = make_client(Lab({"/api/v1/manage/fabrics": json_response(INVENTORY)}))

    assert len(client.list_fabrics()) == 3


def test_aci_fabrics_are_identified_by_management_type() -> None:
    assert is_aci_fabric({"management": {"type": "aci"}}) is True
    assert is_aci_fabric({"management": {"type": "ACI"}}) is True
    assert is_aci_fabric({"management": {"type": "nxos"}}) is False
    assert is_aci_fabric({"category": "aci"}) is False


def test_validation_accepts_a_known_aci_fabric(make_client) -> None:
    client = make_client(Lab({"/api/v1/manage/fabrics": json_response(INVENTORY)}))

    client.validate_fabric("FABRIC-A")


def test_validation_rejects_a_typo_and_lists_the_real_names(make_client) -> None:
    client = make_client(Lab({"/api/v1/manage/fabrics": json_response(INVENTORY)}))

    with pytest.raises(InputError) as caught:
        client.validate_fabric("FABRIC-Q")

    assert caught.value.exit_code == 4
    assert "FABRIC-A, FABRIC-B" in str(caught.value)


def test_validation_rejects_a_non_aci_fabric(make_client) -> None:
    """Only ACI fabrics are supported, so an NX-OS fabric is bad input."""
    client = make_client(Lab({"/api/v1/manage/fabrics": json_response(INVENTORY)}))

    with pytest.raises(InputError, match="not an ACI fabric"):
        client.validate_fabric("NXOS-1")


def test_validation_is_skipped_when_the_inventory_cannot_be_read(make_client) -> None:
    """An unreadable inventory is not evidence the fabric name is wrong."""
    client = make_client(
        Lab({"/api/v1/manage/fabrics": json_response({"message": "boom"}, 500)})
    )

    client.validate_fabric("FABRIC-A")
