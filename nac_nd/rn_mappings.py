"""RN prefix to APIC class mappings for placeholder nodes in DN trees."""

from __future__ import annotations

from typing import Any

RN_PREFIX_CLASSNAME_MAPPINGS: dict[str, dict[str, Any]] = {
    "uni": {"class": "polUni"},
    "userext": {"class": "aaaUserEp"},
    "fabric": {"class": "fabricInst"},
    "hsPols": {"class": "healthPolCont"},
    "infra": {"class": "infraInfra"},
    "tn": {
        "class": "fvTenant",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "epg": {
        "class": "fvAEPg",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "rscons": {
        "class": "fvRsCons",
        "keys": [{"attribute": "tnVzBrCPName", "regex": ".*"}],
    },
    "rsprov": {
        "class": "fvRsProv",
        "keys": [{"attribute": "tnVzBrCPName", "regex": ".*"}],
    },
    "rsdomAtt": {
        "class": "fvRsDomAtt",
        "keys": [{"attribute": "tDn", "regex": r"(?<=\[).*(?=\])"}],
    },
    "attenp": {
        "class": "infraAttEntityP",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "rsdomP": {
        "class": "infraRsDomP",
        "keys": [{"attribute": "tDn", "regex": r"(?<=\[).*(?=\])"}],
    },
    "ap": {
        "class": "fvAp",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "BD": {
        "class": "fvBD",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "subnet": {
        "class": "fvSubnet",
        "keys": [{"attribute": "ip", "regex": r"(?<=\[).*(?=\])"}],
    },
    "rsBDToOut": {
        "class": "fvRsBDToOut",
        "keys": [{"attribute": "tnL3extOutName", "regex": ".*"}],
    },
    "brc": {
        "class": "vzBrCP",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "subj": {
        "class": "vzSubj",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "rssubjFiltAtt": {
        "class": "vzRsSubjFiltAtt",
        "keys": [{"attribute": "tnVzFilterName", "regex": ".*"}],
    },
    "flt": {
        "class": "vzFilter",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "e": {
        "class": "vzEntry",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "out": {
        "class": "l3extOut",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "instP": {
        "class": "l3extInstP",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "extsubnet": {
        "class": "l3extSubnet",
        "keys": [{"attribute": "ip", "regex": r"(?<=\[).*(?=\])"}],
    },
    "rttag": {
        "class": "l3extRouteTagPol",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "rspathAtt": {
        "class": "fvRsPathAtt",
        "keys": [{"attribute": "tDn", "regex": r"(?<=\[).*(?=\])"}],
    },
    "leaves": {
        "class": "infraLeafS",
        "keys": [
            {"attribute": "name", "regex": ".*(?=-typ-)"},
            {"attribute": "type", "regex": r"(?<=-typ-).*"},
        ],
    },
    "taboo": {
        "class": "vzTaboo",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "destgrp": {
        "class": "spanDestGrp",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "srcgrp": {
        "class": "spanSrcGrp",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "spanlbl": {
        "class": "spanSpanLbl",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "ctx": {
        "class": "fvCtx",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "pol": {
        "class": "coopPol",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
    "format": {
        "class": "datetimeFormat",
        "keys": [{"attribute": "name", "regex": ".*"}],
    },
}
