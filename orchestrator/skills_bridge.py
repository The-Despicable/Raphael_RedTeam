import logging

logger = logging.getLogger("skills_bridge")


class SkillsBridge:
    def __init__(self) -> None:
        self.skills: dict[str, object] = {}

    def get_skill(self, name: str) -> object | None:
        return self.skills.get(name)

    def register_skill(self, name: str, skill: object) -> None:
        self.skills[name] = skill
