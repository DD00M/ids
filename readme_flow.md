
sed -i 's/id\.//g' http.log 


#TODO save function si retrain si compare

#TODO integrare cu interfata si security onion
 -> pagina principala
 -> regulile vor fi luate si parsate din fisierele de reguli
 -> pe baza anomaliilor detectate din fisierele de trafic vom putea adauga reguli noi, care se vor adauga fisierului si vor restarta serviciul, astfel incat la venirea unui nou atac similar, acesta sa fie detectat

#TODO fa statistica atunci cand se porneste fereastra cu ce e in baza de date:
your database currently consists {x} trained models for {http} with {IForest}

teoretic, fisierul de log-uri se updateaza constant, se scrie in el
daca se da retrain pentru un protocol si un algoritm, se da drop la modelul anterior, se reincarca fisierul de log-uri, si numarul de clusere si pca 

ni se arata statistica daca apasam ok si nu avem niciun fisier selectat alegem algoritmul pentru care avem un model in baza de date si ni se va arata un grafic
daca in statistici zice ca nu avem niciun model in bd, selectam un fisier si facem train pe el apoi save


sudo snort -A console -q -c /etc/snort/snort.conf -i ens33
cat /etc/snort/rules/local.rules
sudo nano /var/log/snort/alert