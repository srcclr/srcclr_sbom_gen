from setuptools import setup, find_packages

from srcclr_sbom_gen.srcclr_sbom_gen import __version__

setup(
    name="srcclr_sbom_gen",
    version=__version__,
    author="Hanley Shun",
    author_email="hshun@veracode.com",
    description="Parses srcclr scan results and converts to CycloneDX [https://cyclonedx.org/] SBOM JSON format.",
    url="https://github.com/srcclr/srcclr_sbom_gen",
    license="Veracode",
    packages=["srcclr_sbom_gen"],
    scripts=["srcclr_sbom_gen/srcclr_sbom_gen.py"]
)
