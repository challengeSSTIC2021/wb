## Solution avec PyQBDI

Deux solutions possibles sont implémentés dans le fichier ``solver.py``.

### Extraction de la clef

Utilisation de 'self.extract_key()'

### Utilisation de l'oracle pour casser le prefix

Utilisation de 'tracer.generate_mask(oracle)' avec la fonction oracle en paramêtre.

Dure environ une minute.

## Serveur d'interposition avec vlc

Le fichier ``server.py`` permet de créer un proxy avec le serveur de clef et de casser la whitebox quand
une erreur de permission survient.
