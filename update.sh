#!/bin/bash

git add .
DATE=$( echo date)
git commit -m "$DATE"
git push -u origin master
