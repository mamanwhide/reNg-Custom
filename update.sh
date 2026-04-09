#!/bin/bash
set -e

echo "Do you want to apply your local changes after updating? (y/n)"
read answer
answer=$(echo $answer | tr '[:upper:]' '[:lower:]')

if [[ $answer == "y" ]]; then
  make down && git stash save && git pull && git stash apply && make build && make up
elif [[ $answer == "n" ]]; then
  echo "WARNING: This will discard your local changes. Are you sure? (y/n)"
  read confirm
  confirm=$(echo $confirm | tr '[:upper:]' '[:lower:]')
  if [[ $confirm == "y" ]]; then
    make down && git stash && git stash drop && git pull && make build && make up
  else
    echo "Update cancelled."
    exit 0
  fi
else
  echo "Invalid input. Please enter 'y' or 'n'."
fi
