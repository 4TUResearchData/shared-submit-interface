shared-submit-interface
=======================

This package provides a web service to submit data to either
DANS or 4TU.ResearchData.

## Development setup

To create a development environment, use the following snippet:
```bash
python -m venv shared-submit-interface-env
. shared-submit-interface-env/bin/activate
cd /path/to/the/repository/checkout/root
pip install -r requirements.txt
```

To get an interactive development environment, use:
```python
sed -e 's/@VERSION@/0.0.1/g' pyproject.toml.in > pyproject.toml
pip install --editable .
shared-submit-interface --config-file etc/shared-submit-interface.xml
```

#### Keeping your development environment up-to-date

To update packages in the virtual environment, use the following command
inside an activated virtual environment:
```bash
pip freeze | grep -v "shared-submit-interface.git" | cut -d= -f1 | xargs -n1 pip install -U
```
