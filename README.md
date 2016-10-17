#RP

a http proxy server. 
- you can add your logic before really request.

## How to Use
./rp -l 10.245.65.27:80 -p 127.0.0.1:80
- 10.245.65.27.80 is Foreign visible IP[eth1]（Users direct access to the address）
- 127.0.0.1:80 is The actual provide service‘s IP (it can be a apache server)
