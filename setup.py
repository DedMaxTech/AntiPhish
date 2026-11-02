"""Include the curated resource catalog in wheels as well as source checkouts."""
from pathlib import Path
import shutil
from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithResources(build_py):
    def run(self):
        super().run()
        destination = Path(self.build_lib) / "antiphish" / "resources"
        destination.mkdir(parents=True, exist_ok=True)
        for path in (Path(__file__).parent / "resources").glob("*.json"):
            shutil.copy2(path, destination / path.name)
        gallery = Path(__file__).parent / 'resources' / 'logo-gallery'
        if gallery.is_dir():
            shutil.copytree(gallery, destination / 'logo-gallery', dirs_exist_ok=True)


setup(cmdclass={"build_py":BuildWithResources})
