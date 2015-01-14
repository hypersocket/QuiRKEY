QuiRKEY
=======

A web-based authentication mechanism that uses QR codes to perform public key authentication.

Still confused?
----

You may be familiar with Public Key authentication if you have ever used the popular SSH (Secure Shell) protocol to access remote servers. This mechanism provides you with a private key which you keep secret and a public key that you distribute to servers you want to login to. You then access the server giving the SSH client your private key and it authenticates with the server by signing an authentication request with its private key and some other session specific variables. The server checks these variables and the signature and if all is well it gives you access to the system. 

This web-based mechanism works in a similar way. You register your phone with the server by scanning a QR code it presents on screen. A trust relationship is then established between your phone and the server, your private key is kept secret on your phone, whilst the public key is added to the server.

When you want to login, you access the web servers URL and it presents you with another QR code. You scan this and your mobile signs the authentication request with its private key and session variables which authenticates you with the server.

We call this QuiRKEY Authentication and any web-based service could integrate this following our examples.


