# Frightening Network Webapp
A fork of the frightening network but designed to work as a web wallet

# What is this?

The [frightening network](https://github.com/supertestnet/frightening-network) is my own personal version of the lightning network except you're much more likely to lose all your money. The one I just linked to only supports payments between Vicky and Paul. In this version, Paul runs a copy of LND and lets Vicky pay him to send "real" lightning payments to other people on the ntwork. He also forwards payments to her from other people on the network.

# So it's like lightning in the browser?

Yes.

# Didn't Mutiny already do that?

Yes.

# Why are you doing it too?

Because I like Mutiny and I want to make on too. This one is also easier for me to customize baus it is in javasCript, which is a language I understand, whereas Mutiny is in rust, which I don't.

# Does it work?

Not all the way, not yet. On regtest, Vicky can open a channel with Bob and force close it, but that's it. I'm still working on making state updates work like they do in the other version of Frightening Network. Part of the effort involves replacing the copy-paste parts with GET and POST requests, and that's coming along nicely. This one also has buttons, though they mostly don't work yet. When (if) it all ends up working, I hope to move it over to mainnet so people can play with it using real funds. Help me improve it! Maybe one day it will be awesome.

# Instructions for installing and running it

- download this repo
- go into the directory
- run `npm init -y`
- ensure you are using nodejs v19.9.0 (I did this by installing `nvm` and running `nvm install 19`)
- install the dependencies: `npm i @cmdcode/tapscript noble-secp256k1 @dashincubator/ripemd160 bolt11`
- make it a module by modifying package.json to add this key/value pair: `"type": "module",` under `"main": "index.js",`
- run the app with node index.js
- open the vicky.html file in your browser
- click Open Channel and follow the prompts
- The Send and Receive buttons don't work yet
- But you can force close your channel by getting your three force close transactions from your console and manually broadcasting them
- Use these commands:
- `console.log( vicky_channels[ Object.keys( vicky_channels )[ 0 ] ][ "force_close_txs" ][ "to_reveal" ] )` <-- broadcast that
- `console.log( vicky_channels[ Object.keys( vicky_channels )[ 0 ] ][ "force_close_txs" ][ "to_delay" ] )` <-- broadcast that
- `console.log( vicky_channels[ Object.keys( vicky_channels )[ 0 ] ][ "force_close_txs" ][ "final_tx" ] )` <-- broadcast that after waiting 7 blocks
- Yay! You opened a channel and force closed it! Now I just need to make the other stuff work and we'll be in business
