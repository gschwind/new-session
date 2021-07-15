# Background

I implemented _new-session_ to test a KDE plasma session on PinePhone. The issue is that on mobile device you may not have a keyboard connected and it's dificult to open a session in new VT. Moreover with systemd once you are in a given session it is intensionnaly dificult to escape this session. For those reasons I wrote _new-session_ to do the following this:
* login a new user from root using PAM.
* allocating an unsued VT for that user
* openning the session using PAM while escaping the current session, ensuring a fresh systemd session known by logind (loginctl)
* cleanup and setup the user environnment
* starting the given command on the allocated VT

In my case I use _new-session_ to start a session on new VT from SSH.

I share this program as it is under GPL. it can be used as a tutorial to learn how a modern linux session is openned. In that regards I extensively comment the code with my imcomplete understanding. The code is a developement tools and I recommand to look at the code before using it because I do what I need and no more, and obviously what I need may not be what you need.

Another remarks, the code bind the stdin of the new program to the new VT (TTY) but it does keep stdout and stderr to the calling TTY. That mean that anny output of the running command goes to the calling terminal and not to the new terminal. This is convinient in my development use case.

Contributions to fix, to add feature or to make my program more versatile are wellcome.

