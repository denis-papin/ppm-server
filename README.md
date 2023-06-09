PPM-SERVER 


* Never re-write the file, use a new timestamped file
* Clean the file history
* Implement the deletion (active y/n)

PPM (client)

* Put the ppm-poc (client) source into the group folder with ppm-server
* Rename the ppm-poc project to ppm
* Login box
* Change / New box
* Upper status bar (login, file timestamp) 


Implement the central server communication with a matching code 

 - User : 
 - Clé :  
 - Mot de passe :
(une seule fois)

Every time we have a new device to peer, generate a matching code.

The matching will stay valid until 
    we receive incorrect sync data during the sync 

## Cloud sync

In order to cloud sync we must provide the user the ability to authenticate on a remote server.
The original encryption password (OEP) cannot be transmitted to the server, neither the user name.

So, when a new user is created (user/password (OEP)), we not only setup the local context for encryption 
but we will also generate 
    * A uuid for the user name 
    * The OEP hash

Then those credentials will be used to authenticate the user on the server.

In return of the auth. process, a session id with a limited life time (1 day) will be provided.

Note : Today, the username is used in the local login process. It's enough but in the case of 
a remote login process (RPL), the username uniqueness is important, 
so a unique user ID must be created somewhere.
The principle of separation (Local/Cloud) makes use reluctant to keep a hard link between username and userID.

Solution : A user ID is created / retrieved  *as soon as* a cloud option is enabled (FT-COE/COE)

1. The user name must be unique (ex : email address), 
   It will be checked as soon as the cloud option is enabled (COE)
2. A unique user ID will be generated (FT-COE) or retreived (COE), hash(email address) and userID will be kept on the server.

3. When a user change it's user name (email address) 
   1. COE : we change the information locally and replace the username hash in the remote DB
   2. no COE :  we change the information locally but
      In this case, the server has no data about the current account, so nothing to do remotely.

==> THIS DOES NOT WORK FOR EXISTING ACCOUNT !!!

ATTENTION : Rien de fonctionne de tout cela car tout changement sur un poste 
doit être répercuté sur les autres postes.



