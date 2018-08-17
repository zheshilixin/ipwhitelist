import commands
cmd1 = '/etc/sqlalert-1.0.4/bin/sqlalert -e . -t /etc/sqlalert-1.0.4/rules/test/compare3data.rule'
cmd2 = 'nfdump -R  /home/stevens/metadata/tcp/2018/08/01/02/nfcapd_tcp.20180801022300:nfcapd_tcp.20180801022900 -N -p 1,4,10,13 -o "fmt:%sa %fl"'
output1 = commands.getstatusoutput(cmd1)
output2 = commands.getstatusoutput(cmd2)
print output1
print output2
