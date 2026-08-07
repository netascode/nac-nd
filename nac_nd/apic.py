"""APIC managed-object tree used when building Nexus Dashboard upload payloads.

Tree insertion and JSON serialisation follow the same approach as nexus-pcv.
"""

from __future__ import annotations

import json
from typing import Any


class ApicObject:
    def __init__(
        self,
        cl: str | None,
        attributes: dict[str, Any],
        children: list[ApicObject],
        parent: ApicObject | None,
    ) -> None:
        self.cl = cl
        self.attributes = attributes
        self.children = children
        self.parent = parent

    def update(
        self,
        attributes: dict[str, Any],
        children: list[ApicObject],
    ) -> None:
        self.attributes.update(attributes)
        for child in children:
            dn = child.attributes.get("dn")
            name = child.attributes.get("name")
            found = False
            if dn is not None:
                for existing in self.children:
                    if existing.attributes.get("dn") == dn:
                        if child.cl != existing.cl:
                            continue
                        existing.update(child.attributes, child.children)
                        found = True
            if found:
                continue
            if name is not None:
                for existing in self.children:
                    if (
                        existing.attributes.get("name") == name
                        and child.cl == existing.cl
                    ):
                        existing.update(child.attributes, child.children)
                        found = True
            if found:
                continue
            self.children.append(
                ApicObject(child.cl, child.attributes, child.children, self)
            )

    def find(self, dn: str = "", cl: str = "") -> list[ApicObject]:
        result: list[ApicObject] = []
        if not dn and not cl:
            return result
        if not cl:
            if self.attributes.get("dn") == dn:
                result.append(self)
        elif not dn:
            if self.cl == cl:
                result.append(self)
        elif self.attributes.get("dn") == dn and self.cl == cl:
            result.append(self)
        for child in self.children:
            result.extend(child.find(dn=dn, cl=cl))
        return result

    def _index_of_last_dn_delimiter(self, dn: str) -> int:
        escaped = 0
        index = len(dn) - 1
        for char in reversed(dn):
            if char == "]":
                escaped += 1
            elif char == "[":
                escaped -= 1
            elif char == "/" and escaped == 0:
                return index
            index -= 1
        return -1

    def insert(self, obj: ApicObject | None) -> None:
        if obj is None:
            return
        dn = obj.attributes["dn"]
        matches = self.find(dn=dn)
        if matches:
            matches[0].update(obj.attributes, obj.children)
            return
        index = self._index_of_last_dn_delimiter(dn)
        if index == -1:
            self.children.append(obj)
            obj.parent = self
            return
        parent_dn = dn[:index]
        parent_matches = self.find(dn=parent_dn)
        if parent_matches:
            parent_matches[0].children.append(obj)
            obj.parent = parent_matches[0]
            return
        placeholder = ApicObject(None, {"dn": parent_dn}, [obj], None)
        obj.parent = placeholder
        self.insert(placeholder)

    def __getitem__(self, key: str | int) -> ApicObject | Any | None:
        if isinstance(key, str):
            return self.attributes.get(key)
        return self.children[key]

    def __str__(self) -> str:
        attr_string = ", ".join(
            f'"{key}": {json.dumps(value)}' for key, value in self.attributes.items()
        )
        child_string = ", ".join(str(child) for child in self.children)
        return (
            f'{{"{self.cl}": {{"attributes": {{{attr_string}}}, '
            f'"children": [{child_string}]}}}}'
        )
