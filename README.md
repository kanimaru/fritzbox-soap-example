# Examples for Fritzbox API / TR064

There is no good documentation / library for FB in golang outside. So here are some examples how to start.
The implementation should provide a start into the development they are not feature complete and maybe 
FB team will break it. 

In this repo are 2 examples how to get the session id once via web login (lua_login.go) and one via SOAP directly (soap_login.go)
You will need this session ID for more advanced requests like getting all connected wlan devices. In my tests I saw no 
difference between these 2 SIDs.

## Further resources / credit

Digest Implementation for Soap: https://stackoverflow.com/questions/39474284/how-do-you-do-a-http-post-with-digest-authentication-in-golang

Digest Implementation in general: https://en.wikipedia.org/wiki/Digest_access_authentication

Idea how to call the FB Soap service: https://github.com/jhubig/FritzBoxShell
