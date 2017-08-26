# duohtrp
Golang htaccess reverse proxy with Duo 2 Factor Authentication

Proof of concept for DUO 2 Factor Authentication using htaccess file and
a DUO 2 Factor Push on your Smartphone.




1. Make sure you generate a correct htpassword file.
2. Make sure you setup an API ikey and skey from the DUO application admin page.
3. Edit the config.toml for your settings.
4. Run the backend 'hello world' server. It listens on localhost
5. Run the duohtrp, It will bind to '*:9999'and authenticate you to the backend.


Next version TLS/ SSL support.

Enjoy
