from dataclasses import dataclass, field
from typing import List

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class Stats:
    avg_processing_time: float = field(
        hash=False, repr=True, compare=False, default=None)
    blocked_filtering: List[int] = field(
        hash=False, repr=True, compare=False, default=None)
    dns_queries: List[int] = field(hash=False, repr=True, compare=False, default=None)
    num_blocked_filtering: int = field(
        hash=False, repr=True, compare=False, default=None)
    num_dns_queries: int = field(hash=False, repr=True, compare=False, default=None)
    num_replaced_parental: int = field(
        hash=False, repr=True, compare=False, default=None)
    num_replaced_safebrowsing: int = field(
        hash=False, repr=True, compare=False, default=None)
    num_replaced_safesearch: int = field(
        hash=False, repr=True, compare=False, default=None)
    replaced_parental: List[int] = field(
        hash=False, repr=True, compare=False, default=None)
    replaced_safebrowsing: List[int] = field(
        hash=False, repr=True, compare=False, default=None)
    time_units: str = field(hash=False, repr=True, compare=False, default=None)
    top_blocked_domains: List[dict] = field(
        hash=False, repr=True, compare=False, default=None)
    top_clients: List[dict] = field(hash=False, repr=True, compare=False, default=None)
    top_queried_domains: List[dict] = field(
        hash=False, repr=True, compare=False, default=None)
