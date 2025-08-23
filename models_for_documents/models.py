from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Section:
    title: str
    content: str = ""
    subsections: List['Section'] = field(default_factory=list)
    effort: Optional[Dict[str, float]] = None  # New format: {"effort_value": float, "effort_included": int}

    def to_dict(self):
        return {
            "title": self.title,
            "content": self.content,
            "effort": self.effort,
            "children": [s.to_dict() for s in self.subsections]
        }

@dataclass
class Chapter:
    title: str
    content: str = ""
    sections: List[Section] = field(default_factory=list)
    effort: Optional[Dict[str, float]] = None  # New format: {"effort_value": float, "effort_included": int}

    def to_dict(self):
        return {
            "title": self.title,
            "content": self.content,
            "effort": self.effort,
            "children": [section.to_dict() for section in self.sections]
        }

@dataclass
class DocumentTemplate:
    title: str
    chapters: List[Chapter] = field(default_factory=list)

    def to_dict(self):
        return {
            "title": self.title,
            "children": [chapter.to_dict() for chapter in self.chapters]
        }
