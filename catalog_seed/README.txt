Folder format for bulk import:

catalog_seed/
  P1/
    US__United States.txt
    MA__Morocco.txt
  P2/
    US__United States.txt

Each TXT file is opaque proxy content. The API returns it exactly to an
authorized app. The part before __ is the API id; the part after __ is the
dropdown label. A simple Morocco.txt file is also accepted.

Import locally or from a Render Shell:
python manage.py import_proxy_catalog catalog_seed --disable-missing

Never commit real proxy credentials to a public Git repository. Prefer the
encrypted Django admin form for production, or use a temporary private import
source and delete the plaintext files immediately after import.
