#!/bin/bash
files=$(ls /home/cristiana/pyqt/two_windows/logs/*.log)
for file in $files
do
        sed -i -e '1,6d;8d' $file && sed -i '$d' $file  && sed -i -e 's/#fields\t//g' $file
done
rm /home/cristiana/pyqt/two_windows/logs/capfile*