#### XX-Net-Linux 3.13.1
Mini version of [XX-Net](https://github.com/XX-net/XX-Net) for Linux user.

Usage: 

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
    /usr/sbin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml 
    chromium --proxy-server="http://127.0.0.1:8087"
    
    # Firefox 
    
    about:config
    network.proxy.type 1     
    network.proxy.http 127.0.0.1
    network.proxy.http_port 8087
    network.trr.mode 2
    network.trr.uri https://mozilla.cloudflare-dns.com/dns-query
    

Note: all XX-Net 3.13.1 related Python 2.7.16rc1 libs are latest version and installed by pip2.

    pip2 install hyper hyperframe ipaddress pyasn1 pyOpenSSL PySocks setuptools -U
    
    # pip2 list
    
    Package      Version
    ------------ -------
    asn1crypto   0.24.0 
    cffi         1.12.1 
    cryptography 2.5    
    enum34       1.1.6  
    h2           3.1.0  
    hpack        3.0.0  
    hyper        0.7.0  
    hyperframe   5.2.0  
    ipaddress    1.0.22
    pip          19.0.2 
    pyasn1       0.4.5  
    pycparser    2.19   
    pyOpenSSL    19.0.0 
    PySocks      1.6.8  
    setuptools   40.8.0 
    six          1.12.0
