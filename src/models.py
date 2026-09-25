from dataclasses import dataclass
from typing import Optional


@dataclass
class Entity:
    id: str
    type: str
    name: str
    criticality: Optional[str] = None


@dataclass
class Relationship:
    source: str
    target: str
    type: str