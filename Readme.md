cand nu merge git remote set-url origin git@github.com:marioara-biblioteca/siem.git
suricata:
sudo suricata -T -c /etc/suricata/suricata.yaml -v pentru verificare reguli
sudo kill -usr2 $(pidof suricata) pt restart
