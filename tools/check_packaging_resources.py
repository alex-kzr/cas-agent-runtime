"""Static check of CAS's explicit Hatch packages/force-include paths, not a build.

Models selected-then-forced archive destinations seen in pinned Hatchling 1.32.4.
It does not implement Hatch's VCS/ignore/hook selection or prove buildability.
Actual sdist/wheel byte audits remain mandatory in clean-build acceptance.
"""
import json
import tomllib
from pathlib import Path, PurePosixPath

METADATA = {
    'backend.json', 'client.json', 'image-defaults.json',
    'image-env.json', 'image.json', 'server-version.json',
}


def destinations(root: Path, config: dict) -> dict[str, Path]:
    wheel = config['tool']['hatch']['build']['targets']['wheel']
    selected = {}

    def add(source, destination):
        dest = PurePosixPath(destination)
        if dest.is_absolute() or '..' in dest.parts or '\\' in destination:
            raise ValueError('UNSAFE_DESTINATION')
        if destination in selected:
            raise ValueError('DUPLICATE_WHEEL_DESTINATION:' + destination)
        selected[destination] = source

    for package in wheel['packages']:
        base = root / package
        if not base.is_dir():
            raise ValueError('PACKAGE_MISSING')
        for source in sorted(base.rglob('*')):
            if source.is_file() and '__pycache__' not in source.parts:
                add(source, (PurePosixPath(base.name) / source.relative_to(base).as_posix()).as_posix())
    for source_name, target in wheel.get('force-include', {}).items():
        source_root = root / source_name
        if not source_root.exists():
            raise ValueError('FORCED_SOURCE_MISSING')
        files = sorted(p for p in source_root.rglob('*') if p.is_file()) if source_root.is_dir() else [source_root]
        for source in files:
            relative = source.relative_to(source_root).as_posix() if source_root.is_dir() else ''
            add(source, (PurePosixPath(target) / relative).as_posix())
    return selected


def check(root: Path, config=None):
    if config is None:
        config = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    result = destinations(root, config)
    if config['project']['name'] == 'cas-agent-runtime':
        prefix = 'agent_runtime/providers/claude/working_cells/metadata/'
        metadata = {p.removeprefix(prefix): source for p, source in result.items() if p.startswith(prefix)}
        if set(metadata) != METADATA:
            raise ValueError('METADATA_COVERAGE_CHANGED')
        for source in metadata.values():
            json.loads(source.read_text(encoding='utf-8'))
    if config['project']['name'] == 'cas-agent-console':
        assets = {p.relative_to(root / 'static').as_posix() for p in (root / 'static').rglob('*') if p.is_file()}
        if not assets or not all('agent_console/static/' + p in result for p in assets):
            raise ValueError('STATIC_ASSET_COVERAGE_CHANGED')
    return {'archive_destinations': len(result), 'duplicate_destinations': False, 'build': 'NOT_RUN'}


if __name__ == '__main__':
    print(json.dumps(check(Path(__file__).resolve().parents[1])))
