"""
SecuraX Scanner Plugin Registry
=================================
Auto-discovery and registration system for scanner plugins.

Usage:
    # Register a plugin manually
    from backend.scanners.sdk.registry import PluginRegistry
    registry = PluginRegistry.instance()
    registry.register(MyScanner)

    # Auto-discover all plugins in a directory
    registry.discover("backend/scanners/plugins/")

    # Run a scanner
    result = registry.run("web_scanner", target="http://example.com")

    # List available scanners
    registry.list_plugins()

Version: 1.0.0
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Optional, Type

from backend.scanners.sdk.base import ScannerPlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Singleton registry for SecuraX scanner plugins.

    Maintains a catalogue of registered scanners and provides
    factory methods for instantiation and invocation.
    """

    _instance: Optional["PluginRegistry"] = None

    def __init__(self):
        self._plugins: dict[str, Type[ScannerPlugin]] = {}

    @classmethod
    def instance(cls) -> "PluginRegistry":
        """Return the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, plugin_cls: Type[ScannerPlugin]) -> None:
        """
        Register a scanner plugin class.

        Args:
            plugin_cls: A subclass of ScannerPlugin.

        Raises:
            TypeError:  If plugin_cls does not subclass ScannerPlugin.
            ValueError: If a plugin with the same name is already registered.
        """
        if not (isinstance(plugin_cls, type) and issubclass(plugin_cls, ScannerPlugin)):
            raise TypeError(f"{plugin_cls!r} must be a subclass of ScannerPlugin")

        name = plugin_cls.name
        if name in self._plugins:
            logger.warning(
                "Plugin '%s' already registered (v%s). Overwriting with v%s.",
                name, self._plugins[name].version, plugin_cls.version
            )

        self._plugins[name] = plugin_cls
        logger.info("Registered scanner plugin: %s v%s", name, plugin_cls.version)

    def unregister(self, name: str) -> bool:
        """
        Unregister a plugin by name.

        Returns:
            True if the plugin was registered; False otherwise.
        """
        if name in self._plugins:
            del self._plugins[name]
            logger.info("Unregistered scanner plugin: %s", name)
            return True
        return False

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover(self, plugins_dir: str | Path) -> int:
        """
        Auto-discover and register all ScannerPlugin subclasses in a directory.

        Searches for Python files in `plugins_dir`, imports them, and registers
        any class that subclasses ScannerPlugin.

        Args:
            plugins_dir: Path to directory containing plugin modules.

        Returns:
            Number of plugins discovered and registered.
        """
        plugins_dir = Path(plugins_dir)
        if not plugins_dir.is_dir():
            logger.warning("Plugin discovery: directory not found: %s", plugins_dir)
            return 0

        count = 0
        for py_file in plugins_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            module_name = f"_securax_plugin_{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None:
                continue

            try:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ScannerPlugin)
                        and attr is not ScannerPlugin
                        and attr.name  # must have a name
                    ):
                        self.register(attr)
                        count += 1

            except Exception as exc:
                logger.error("Failed to load plugin from %s: %s", py_file, exc)

        logger.info("Plugin discovery complete: %d plugins found in %s", count, plugins_dir)
        return count

    # ── Invocation ────────────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[Type[ScannerPlugin]]:
        """Return a plugin class by name, or None if not registered."""
        return self._plugins.get(name)

    def create(self, name: str) -> ScannerPlugin:
        """
        Instantiate a plugin by name.

        Args:
            name: Plugin name as registered.

        Raises:
            KeyError: If no plugin with that name is registered.
        """
        cls = self._plugins.get(name)
        if cls is None:
            available = list(self._plugins.keys())
            raise KeyError(
                f"No scanner plugin named '{name}'. Available: {available}"
            )
        return cls()

    def run(self, name: str, target: str, **options) -> dict:
        """
        Instantiate a plugin and run the full scan pipeline.

        Args:
            name:      Plugin name.
            target:    Scan target (URL, IP, file path).
            **options: Passed to plugin.scan().

        Returns:
            SecuraX-compatible scan_result dict.
        """
        plugin = self.create(name)
        return plugin.run(target, **options)

    # ── Introspection ─────────────────────────────────────────────────────────

    def list_plugins(self) -> list[dict]:
        """Return a list of registered plugin metadata dicts."""
        return [
            {
                "name":               cls.name,
                "version":            cls.version,
                "description":        cls.description,
                "supported_scan_types": cls.supported_scan_types,
            }
            for cls in self._plugins.values()
        ]

    def __len__(self) -> int:
        return len(self._plugins)

    def __repr__(self) -> str:
        return f"<PluginRegistry plugins={list(self._plugins.keys())}>"


# ── Module-level singleton ────────────────────────────────────────────────────
registry = PluginRegistry.instance()
