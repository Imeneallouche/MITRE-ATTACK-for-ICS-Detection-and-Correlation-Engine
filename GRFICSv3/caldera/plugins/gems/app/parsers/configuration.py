import re

from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from app.utility.base_parser import BaseParser

CONFIG_RE = re.compile(r" {2}(\w+)\n")


class Parser(BaseParser):
    def parse(self, blob):
        relationships = []
        for match in CONFIG_RE.findall(blob):
            config = match

            for mp in self.mappers:
                source = self._set_source_value(mp.source)
                target = config

                relationships.append(
                    Relationship(
                        source=Fact(mp.source, source),
                        edge=mp.edge,
                        target=Fact(mp.target, target),
                    )
                )
        return relationships

    def _set_source_value(self, trait):
        value = self.set_value(trait, None, self.used_facts)
        if not value:
            for sf in self.source_facts:
                if sf.trait == trait:
                    value = sf.value
                    break
        return value
