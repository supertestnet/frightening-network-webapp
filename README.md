# Frightening Network Webapp
A fork of the frightening network but designed to work as a web wallet

# What is this?

The [frightening network](https://github.com/supertestnet/frightening-network) is my own personal version of the lightning network except you're much more likely to lose all your money. The original only supports payments between Vicky and Paul. In this version, Paul runs a copy of LND and lets Vicky pay him to send "real" lightning payments to other people on the ntwork. He also forwards payments to her from other people on the network.

# So it's like lightning in the browser?

Yes.

# Didn't Mutiny already do that?

Yes.

# Why are you doing it too?

Because I like Mutiny and I want to make on too. This one is also easier for me to customize baus it is in javasCript, which is a language I understand, whereas Mutiny is in rust, which I don't.

# Does it work?

Not all the way, not yet. On regtest, Vicky can open a channel with Bob and force close it, but that's it. I'm still working on making state updates work like they do in the other version of Frightening Network. Part of the effort involves replacing the copy-paste parts with GET and POST requests, and that's coming along nicely. This one also has buttons, though they mostly don't work yet. When (if) it all ends up working, I hope to move it over to mainnet so people can play with it using real funds. Help me improve it! Maybe one day it will be awesome.
