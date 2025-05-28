# M-Files Python OAuth Demo

## Description

Ce projet est une adaptation Python d’un client M-Files REST API avec authentification OAuth et interface graphique Tkinter, inspiré d’un exemple C#.

## Utilisation

1. Installez les dépendances :

    ```
    pip install -r requirements.txt
    ```

2. Lancez l’interface :

    ```python
    from main_window import MainWindow
    win = MainWindow()
    win.mainloop()
    ```

3. Remplissez `connectionDetails.NetworkAddress` (dans le code ou via l’interface si vous l’adaptez).

## Structure

- `main_window.py` : logique principale et UI
- `mfiles_structs.py` : structures de données M-Files
- `requirements.txt` : dépendances
- `README.md` : ce fichier

## Remarques

- Ce projet est un squelette à adapter à vos besoins réels et à votre environnement M-Files : les structures, endpoints et UI peuvent être enrichis.
