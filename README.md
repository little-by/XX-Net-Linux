#### XX-Net-Linux 3.13.1
Mini version of [XX-Net](https://github.com/XX-net/XX-Net) for Linux user.

Usage: 

    pip2 install hyper hyperframe ipaddress pyasn1 pyOpenSSL PySocks setuptools -U
    
    git clone https://github.com/miketwes/XX-Net-Linux.git
    
    # put your appids in XX-Net-Linux/data/config.json
    
    "GAE_APPIDS": [
        "yourappid1",
        "yourappid2"
    ],

    sudo /etc/init.d/miredo start
    cd XX-Net-Linux/local && python2 proxy.py
    
    # Chromium

    sudo aptitude install dnscrypt-proxy
    # edit /etc/dnscrypt-proxy/dnscrypt-proxy.toml, 
    # change server_names = ['cloudflare'] to server_names = ['cloudflare', 'cloudflare-ipv6']
    # edit /etc/network/interfaces, add line: dns-nameservers 127.0.0.1
    sudo systemctl start dnscrypt-proxy
    chromium --proxy-server="http://127.0.0.1:8087"
    
    # Firefox 
    
    about:config
    network.proxy.type 1     
    network.proxy.http 127.0.0.1
    network.proxy.http_port 8087
    network.trr.mode 2
    network.trr.uri https://mozilla.cloudflare-dns.com/dns-query
    
    # If the Browser say: 'This page isn’t workingIf the problem continues, contact the site owner.  HTTP ERROR 400', 
    # or something like this, please wait for a while(around 1 mins), all will works ok(update: 2019-08-22). 
    



    
  
