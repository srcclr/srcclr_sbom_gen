# srcclr_sbom_gen

Parses srcclr scan results and converts to CycloneDX [https://cyclonedx.org/] SBOM JSON format.

**Installation**:
```
pip3 install git+https://github.com/srcclr/srcclr_sbom_gen
```

**Getting Started**:

  **Method 1 - Import**
  ```
  import srcclr_sbom_gen
  srcclr_sbom_gen.convert('scan.json', 'sbom.json')
  ```

  **Method 2 - Executing from Command Line**
  ```
  srcclr_sbom_gen.py scan.json sbom.json
  ```
