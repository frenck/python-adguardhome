from dataclasses import dataclass, field
from typing import List

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class Filters:
    enabled: bool = field(hash=False, repr=True, compare=False, default=None)
    id: int = field(hash=False, repr=True, compare=False, default=None)
    last_updated: str = field(hash=False, repr=True, compare=False, default=None)
    name: str = field(hash=False, repr=True, compare=False, default=None)
    rules_count: int = field(hash=False, repr=True, compare=False, default=None)
    url: str = field(hash=False, repr=True, compare=False, default=None)


@dataclass_json
@dataclass
class Status:
    enabled: bool = field(hash=False, repr=True, compare=False, default=None)
    interval: int = field(hash=False, repr=True, compare=False, default=None)
    filters: List[Filters] = field(hash=False, repr=True, compare=False, default=None)
    user_rules: List[str] = field(hash=False, repr=True, compare=False, default=None)
