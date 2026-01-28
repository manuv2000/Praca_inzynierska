#!/bin/bash

PYTHON=python
SCRIPT="injector/tools/attacks_menu.py"

# LICZBA OPCJI W MENU (ZMIEN JEŚLI TRZEBA)
MENU_OPTIONS=5

run_choice () {
  local choice=$1
  local times=$2

  for ((i=1; i<=times; i++)); do
    echo "[+] Opcja $choice — iteracja $i"
    echo "$choice" | $PYTHON $SCRIPT
    sleep 0.2
  done
}

# opcja 1 → 17 razy
run_choice 1 17

# pozostałe opcje → po 10 razy
for ((opt=2; opt<=MENU_OPTIONS; opt++)); do
  run_choice $opt 10
done

echo "DONE"
