#!/bin/bash

git status
git pull
git add .
git commit -m "Auto-update"
git push origin master
