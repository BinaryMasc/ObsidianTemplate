#!/bin/bash
python3 crypter.py encrypt
git status
git pull
git add .
git commit -m "Auto-update"
git push origin master
