# README

## Installation

Créer un environnement virtuel Python dans le dossier `env` :

### Windows

1. Ouvrir la console et se déplacer dans ce dossier (reencryption-api)
2. Créer l'environnement virtuel (voir [documentation](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/#creating-a-virtual-environment) pour plus d'info), en entrant les commandes suivantes :
   ```cmd
   py -m pip install --user virtualenv
   py -m venv env
   .\env\Scripts\activate
   ```
3. Installer les dépendances :
   ```cmd
   py -m pip install -r requirements.txt
   ```
4. On peut alors lancer le serveur avec :
   ```cmd
   py server.py
   ```
   ou le client avec :
   ```cmd
   py client.py
   ```
5. Pour sortir de l'environnement virtuel, fermer la console ou écrire :
   ```cmd
   deactivate
   ```

### Linux/Mac

1. Ouvrir un terminal et se déplacer dans ce dossier (reencryption-api)
2. Créer l'environnement virtuel (voir [documentation](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/#creating-a-virtual-environment) pour plus d'info), en entrant les commandes suivantes :
  ```bash
  python3 -m pip install --user virtualenv
  python3 -m venv env
  source env/bin/activate
  ```
3. Installer les dépendances :
  ```bash
  python3 -m pip install -r requirements.txt
  ```
4. On peut alors lancer le serveur avec :
  ```bash
  python3 server.py
  ```
  ou le client avec :
  ```bash
  python3 client.py
  ```
5. Pour sortir de l'environnement virtuel, fermer la console ou écrire :
  ```bash
  deactivate
  ```
