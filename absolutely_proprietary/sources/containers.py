"""Container images (docker, podman): OCI license label + curated list."""

from __future__ import annotations

import json
from collections.abc import Iterable

from absolutely_proprietary import proc
from absolutely_proprietary.models import Package
from absolutely_proprietary.sources.base import Source

LICENSE_LABELS = ("org.opencontainers.image.licenses", "org.label-schema.license", "license")


class Docker(Source):
    name = "docker"
    kind = "container"
    description = "Local container images (OCI license label + curated list)"
    lists = ("containers",)
    tool = "docker"

    def available(self) -> bool:
        return proc.which(self.tool) is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run([self.tool, "image", "ls", "--format", "{{json .}}"])
        if out is None:
            raise RuntimeError(f"`{self.tool} image ls` failed (is the daemon running?)")
        images = []
        for line in out.splitlines():
            row = json.loads(line)
            repo = row.get("Repository", "")
            if repo and repo != "<none>":
                images.append((repo, row.get("Tag", ""), row.get("ID", "")))
        labels = self._labels([image_id for _, _, image_id in images])
        for repo, tag, image_id in images:
            image_labels = labels.get(image_id) or {}
            lic = next((image_labels[k] for k in LICENSE_LABELS if image_labels.get(k)), None)
            yield self.pkg(repo, tag, lic)

    def _labels(self, image_ids: list[str]) -> dict[str, dict[str, str]]:
        if not image_ids:
            return {}
        out = proc.run([self.tool, "image", "inspect", *dict.fromkeys(image_ids)])
        result: dict[str, dict[str, str]] = {}
        for item in json.loads(out) if out else []:
            labels = (item.get("Config") or {}).get("Labels") or {}
            full_id = item.get("Id", "").removeprefix("sha256:")
            for image_id in image_ids:
                if full_id.startswith(image_id.removeprefix("sha256:")):
                    result[image_id] = labels
        return result


class Podman(Docker):
    name = "podman"
    description = "Local podman images (OCI license label + curated list)"
    tool = "podman"
