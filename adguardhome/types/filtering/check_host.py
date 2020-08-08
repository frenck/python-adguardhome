from dataclasses import dataclass, field
from typing import List, Optional

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class Check_Host:
    reason: str = field(hash=False, repr=True, compare=False, default=None)
    filter_id: int = field(hash=False, repr=True, compare=False, default=None)
    rule: str = field(hash=False, repr=True, compare=False, default=None)
    service_name: str = field(hash=False, repr=True, compare=False, default=None)
    cname: str = field(hash=False, repr=True, compare=False, default=None)
    ip_addrs: Optional[List[str]] = field(
        hash=False, repr=True, compare=False, default=None)
