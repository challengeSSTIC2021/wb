## implémentation d'une whitebox Camellia

- ``docker\_script/runner.py`` contient le script docker qui lance la compilation toutes les 5 minutes et copie la whitebox dans le dossier partagée. Ce scipt génére la clef de la whitebox et la clef de chiffrement AES de bibliothèque.
- ``src`` contient les sources statiques (contructeur ELF, implémentation AES, programme de test)
- ``wb_gen/genWhitebox.py`` génère le code python, C (avec ou sans VM) de la whitebox
