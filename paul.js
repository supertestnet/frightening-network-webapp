import { Address, Script, Signer, Tap, Tx } from '@cmdcode/tapscript';
import nobleSecp256k1 from 'noble-secp256k1';
import RIPEMD160 from '@dashincubator/ripemd160';
import crypto from 'crypto';
import bolt11 from 'bolt11';
import http from 'http';
import url from 'url';
import fs from 'fs';
var tapscript = {
    Address,
    Script,
    Signer,
    Tap,
    Tx
}

if ( fs.existsSync( "db.txt" ) ) {
    var dbtext = fs.readFileSync( "db.txt" ).toString();
    var db = JSON.parse( dbtext );
} else {
    var db = {};
    var texttowrite = JSON.stringify( db );
    fs.writeFileSync( "db.txt", texttowrite, function() {return;});
    var dbtext = fs.readFileSync( "db.txt" ).toString();
    var db = JSON.parse( dbtext );
}

// const http = require( 'http' );
// var url = require( 'url' );
// var nobleSecp256k1 = require( 'noble-secp256k1' );
// var RIPEMD160 = require( '@dashincubator/ripemd160' );

function hexToBytes( hex ) {
    return Uint8Array.from( hex.match( /.{1,2}/g ).map( ( byte ) => parseInt( byte, 16 ) ) );
}

function bytesToHex( bytes ) {
    return bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" );
}

function base64ToHex( str ) {
    var raw = atob( str );
    var result = '';
    var i; for ( i=0; i<raw.length; i++ ) {
        var hex = raw.charCodeAt( i ).toString( 16 );
        result += ( hex.length === 2 ? hex : '0' + hex );
    }
    return result;
}

var rmd160 = s => {
    if ( typeof s == "string" ) s = new TextEncoder().encode( s );
    var hash = RIPEMD160.create();
    hash.update( new Uint8Array( s ) );
    return bytesToHex( hash.digest() );
}

var sha256 = s => {
    if ( typeof s == "string" ) s = new TextEncoder().encode( s );
    return crypto.subtle.digest( 'SHA-256', s ).then( hashBuffer => {
        var hashArray = Array.from( new Uint8Array( hashBuffer ) );
        var hashHex = hashArray
            .map( bytes => bytes.toString( 16 ).padStart( 2, '0' ) )
            .join( '' );
        return hashHex;
    });
}

var getRand = size => bytesToHex(crypto.getRandomValues(new Uint8Array(size)));

function isValidJson( content ) {
    if ( !content ) return;
    try {  
        var json = JSON.parse( content );
    } catch ( e ) {
        return;
    }
    return true;
}

function isValidHex( h ) {
    if ( !h ) return;
    var length = h.length;
    if ( length % 2 ) return;
    try {
        var a = BigInt( "0x" + h, "hex" );
    } catch( e ) {
        return;
    }
    var unpadded = a.toString( 16 );
    var padding = [];
    var i; for ( i=0; i<length; i++ ) padding.push( 0 );
    padding = padding.join( "" );
    padding = padding + unpadded.toString();
    padding = padding.slice( -Math.abs( length ) );
    return ( padding === h );
}

function isValidAddress( address ) {
    try {
        return !!tapscript.Address.decode( address ).script;
    } catch( e ) {return;}
    return;
}

var isValidInvoice = invoice => {
    try {
        return typeof bolt11.decode( invoice ) == "object";
    } catch( e ) {
        return;
    }
}

var purgeUnusedChannelRequests = async () => {
    Object.keys( db ).forEach( item => {
        if ( db[ item ].length != 2 ) return;
        var now = Math.floor( Date.now() / 1000 );
        if ( db[ item ][ 0 ] + 3600 * 24 < now ) {
            delete db[ item ];
            var texttowrite = JSON.stringify( db );
            fs.writeFileSync( "db.txt", texttowrite, function() {return;});
        }
    });
}

var getInvoicePmthash = invoice => {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "payment_hash" ) {
            var pmthash = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return pmthash;
}

var sendResponse = ( response, data, statusCode, content_type ) => {
    if ( response.finished ) return;
    response.setHeader( 'Access-Control-Allow-Origin', '*' );
    response.setHeader( 'Access-Control-Request-Method', '*' );
    response.setHeader( 'Access-Control-Allow-Methods', 'OPTIONS, GET' );
    response.setHeader( 'Access-Control-Allow-Headers', '*' );
    response.setHeader( 'Content-Type', content_type[ "Content-Type" ] );
    response.writeHead( statusCode );
    response.end( data );
};

var collectData = ( request, callback ) => {
    var data = '';
    request.on( 'data', ( chunk ) => {
        data += chunk;
    });
    request.on( 'end', () => {
        callback( data );
    });
};

const requestListener = async function( request, response ) {
    var parts = url.parse( request.url, true );
    var $_GET = parts.query;
    if ( request.method === 'GET' ) {
        if ( parts.path == "/api/v1/request_channel" || parts.path == "/api/v1/request_channel/" ) {
            await purgeUnusedChannelRequests();
            var privkey = bytesToHex( nobleSecp256k1.utils.randomPrivateKey() );
            var pauls_key = nobleSecp256k1.getPublicKey( privkey, true );
            var pauls_publication_preimage = bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 32 );
            var pauls_publication_hash = rmd160( hexToBytes( pauls_publication_preimage ) );
            var pauls_revocation_preimage = bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 32 );
            var pauls_revocation_hash = rmd160( hexToBytes( pauls_revocation_preimage ) );
            var channel_identifier = bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 32 );
            var transitioning_to = 0;
            var msgnum = 0;
            var msg_to_sign = `${channel_identifier}${transitioning_to}${msgnum}${pauls_key}${pauls_publication_hash}${pauls_revocation_hash}`;
            var msghash = await sha256( msg_to_sign );
            var sig = await nobleSecp256k1.sign( msghash, privkey );
            var data_for_vicky = [ msgnum, channel_identifier, sig, pauls_key, pauls_publication_hash, pauls_revocation_hash ];
            var full_data = [ msgnum, channel_identifier, sig, pauls_key, pauls_publication_hash, pauls_revocation_hash, privkey, pauls_publication_preimage, pauls_revocation_preimage ];
            db[ channel_identifier ] = [ Math.floor( Date.now() / 1000 ), full_data ];
            var texttowrite = JSON.stringify( db );
            fs.writeFileSync( "db.txt", texttowrite, function() {return;});
            //todo: save data_for_vicky in a db for 24 hours. If she uses it, don't delete it, but instead mark it as
            //exclusively "for" her pubkey's use -- that way no one but her can use this info
            return sendResponse( response, JSON.stringify( data_for_vicky ), 200, {'Content-Type': 'application/json'} );
        }
        return sendResponse( response, `404 page not found`, 200, {'Content-Type': 'text/plain'} );
    } else if ( request.method === 'POST' ) {
        collectData(request, async ( formattedData ) => {
            if ( parts.path == "/api/v1/make_channel" || parts.path == "/api/v1/make_channel/" ) {
                //ensure the user sent what you expect
                var is_valid_json = isValidJson( formattedData );
                if ( !is_valid_json ) return;
                var arr = JSON.parse( formattedData );
                if ( arr.length != 4 ) return;
                //item 0 should be the msgnum, which should be 1
                if ( arr[ 0 ] != 1 ) return;
                //item 1 should be the channel id
                if ( !isValidHex( arr[ 1 ] ) || arr[ 1 ].length != 32 ) return;
                if ( !Object.keys( db ).includes( arr[ 1 ] ) ) return;
                //item 2 should be an ecdsa signature
                if ( !isValidHex( arr[ 2 ] ) || arr[ 2 ].length > 144 ) return;
                //item 3 should be a json with certain key/value pairs
                if ( typeof arr[ 3 ] != "object" ) return;
                if ( !( "prefunding_txid" in arr[ 3 ] ) || !( "prefunding_vout" in arr[ 3 ] ) ) return;
                if ( !( "prefunding_amt" in arr[ 3 ] ) || !( "vickys_key" in arr[ 3 ] ) ) return;
                if ( !( "vickys_publication_hash" in arr[ 3 ] ) || !( "vickys_revocation_hash" in arr[ 3 ] ) ) return;
                if ( !( "vickys_address" in arr[ 3 ] ) || !( "prefunding_address" in arr[ 3 ] ) ) return;
                //validate that each key/value pair is what you expect
                if ( !isValidHex( arr[ 3 ][ "prefunding_txid" ] ) || arr[ 3 ][ "prefunding_txid" ].length != 64 ) return;
                if ( typeof arr[ 3 ][ "prefunding_vout" ] != "number" || arr[ 3 ][ "prefunding_vout" ] > 4_294_967_295 ) return;
                if ( arr[ 3 ][ "prefunding_vout" ] < 0 || typeof arr[ 3 ][ "prefunding_amt" ] != "number" ) return;
                if ( arr[ 3 ][ "prefunding_amt" ] > 2_100_000_000_000_000 || typeof arr[ 3 ][ "prefunding_amt" ] < 294 ) return;
                if ( !isValidHex( arr[ 3 ][ "vickys_key" ] ) || arr[ 3 ][ "vickys_key" ].length != 66 ) return;
                if ( !isValidHex( arr[ 3 ][ "vickys_publication_hash" ] ) || arr[ 3 ][ "vickys_publication_hash" ].length != 40 ) return;
                if ( !isValidHex( arr[ 3 ][ "vickys_revocation_hash" ] ) || arr[ 3 ][ "vickys_revocation_hash" ].length != 40 ) return;
                if ( !isValidAddress( arr[ 3 ][ "vickys_address" ] ) || !isValidAddress( arr[ 3 ][ "prefunding_address" ] ) ) return;
                //check the signature, and if that checks out, add a channel object to the
                //entry and give Vicky signatures for a refund
                var pauls_key = db[ arr[ 1 ] ][ 1 ][ 3 ];
                var pauls_publication_hash = db[ arr[ 1 ] ][ 1 ][ 4 ];
                var pauls_revocation_hash = db[ arr[ 1 ] ][ 1 ][ 5 ];
                var privkey = db[ arr[ 1 ] ][ 1 ][ 6 ];
                var pauls_publication_preimage = db[ arr[ 1 ] ][ 1 ][ 7 ];
                var pauls_revocation_preimage = db[ arr[ 1 ] ][ 1 ][ 8 ];
                var data_from_vicky = arr;
                var prefunding_txid = data_from_vicky[ 3 ][ "prefunding_txid" ];
                var prefunding_vout = data_from_vicky[ 3 ][ "prefunding_vout" ];
                var prefunding_amt = data_from_vicky[ 3 ][ "prefunding_amt" ];
                var vickys_key = data_from_vicky[ 3 ][ "vickys_key" ];
                var vickys_publication_hash = data_from_vicky[ 3 ][ "vickys_publication_hash" ];
                var vickys_revocation_hash = data_from_vicky[ 3 ][ "vickys_revocation_hash" ];
                var vickys_address = data_from_vicky[ 3 ][ "vickys_address" ];
                var prefunding_address = data_from_vicky[ 3 ][ "prefunding_address" ];
                var channel_identifier = data_from_vicky[ 1 ];
                var transitioning_to = 0;
                var msgnum = 1;
                var msg_to_sign = `${channel_identifier}${transitioning_to}${msgnum}${JSON.stringify(data_from_vicky[ 3 ])}`;
                var msghash = await sha256( msg_to_sign );
                var sig = data_from_vicky[ 2 ];
                var sig_is_valid = await nobleSecp256k1.verify( sig, msghash, vickys_key );
                if ( !sig_is_valid ) return;
                //todo: fix the sequence which should be 144 * 7 not 1 * 7
                var refund_scripts = [
                    [ 'OP_RIPEMD160', vickys_publication_hash, 'OP_EQUALVERIFY', 'OP_RIPEMD160', vickys_revocation_hash, 'OP_EQUALVERIFY', pauls_key.substring( 2 ), 'OP_CHECKSIG' ],
                    [ 0, pauls_key.substring( 2 ), 'OP_CHECKSIGADD', vickys_key.substring( 2 ), 'OP_CHECKSIGADD', 2, 'OP_EQUALVERIFY', 1 * 7, 'OP_CHECKSEQUENCEVERIFY', 'OP_0NOTEQUAL' ],
                    [ 'OP_RIPEMD160', pauls_publication_hash, 'OP_EQUALVERIFY', 'OP_RIPEMD160', pauls_revocation_hash, 'OP_EQUALVERIFY', vickys_key.substring( 2 ), 'OP_CHECKSIG' ]
                ];
                var refund_tree = refund_scripts.map( s => tapscript.Tap.encodeScript( s ) );
                var [ refund_tpubkey, cblock ] = tapscript.Tap.getPubKey( "ab".repeat( 32 ), { tree: refund_tree });
                var refund_cblock = cblock;
                var refund_address = tapscript.Address.p2tr.fromPubKey( refund_tpubkey, 'regtest' );
                var tx_funding_script = [
                    2,
                    pauls_key,
                    vickys_key,
                    2,
                    'OP_CHECKMULTISIG'
                ];
                var tx_funding_address = tapscript.Address.p2wsh.fromScript( tx_funding_script, "regtest" );
                var post_funding_script_paul = [
                    'OP_RIPEMD160',
                    pauls_publication_hash,
                    'OP_EQUAL',
                    'OP_NOTIF',
                        'OP_10',
                        'OP_CHECKSEQUENCEVERIFY',
                        'OP_DROP',
                    'OP_ENDIF',
                    2,
                    pauls_key,
                    vickys_key,
                    2,
                    'OP_CHECKMULTISIG'
                ];
                var post_funding_address_paul = tapscript.Address.p2wsh.fromScript( post_funding_script_paul, "regtest" );
                var post_funding_script_vicky = [
                    'OP_RIPEMD160',
                    vickys_publication_hash,
                    'OP_EQUAL',
                    'OP_IF',
                        2,
                        pauls_key,
                        vickys_key,
                        2,
                        'OP_CHECKMULTISIG',
                    'OP_ELSE',
                        'OP_10',
                        'OP_CHECKSEQUENCEVERIFY',
                        'OP_DROP',
                        pauls_key,
                        'OP_CHECKSIG',
                    'OP_ENDIF',
                ];
                var post_funding_address_vicky = tapscript.Address.p2wsh.fromScript( post_funding_script_vicky, "regtest" );
                var prefunding_txdata = tapscript.Tx.create({
                  vin  : [{
                    txid: prefunding_txid,
                    vout: prefunding_vout,
                    prevout: {
                      value: prefunding_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( prefunding_address )
                    },
                  }],
                  vout : [{
                    value: prefunding_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( tx_funding_address )
                  }]
                });
                var prefunding_txhex = tapscript.Tx.encode( prefunding_txdata ).hex;
                var tx_funding_txid = tapscript.Tx.util.getTxid( prefunding_txhex );
                var tx_funding_vout = 0;
                var tx_funding_amt = prefunding_amt - 500;
                var tx_funding_txdata_paul = tapscript.Tx.create({
                  vin  : [{
                    txid: tx_funding_txid,
                    vout: tx_funding_vout,
                    prevout: {
                      value: tx_funding_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( tx_funding_address )
                    },
                  }],
                  vout : [{
                    value: tx_funding_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( post_funding_address_paul )
                  }]
                });
                var sighash = tapscript.Signer.segwit.hash( tx_funding_txdata_paul, 0, { script: tx_funding_script } );
                var tx_funding_pauls_sig = tapscript.Signer.segwit.sign( privkey, tx_funding_txdata_paul, 0, { script: tx_funding_script });
                tx_funding_txdata_paul.vin[ 0 ].witness = [ 0, 0, tx_funding_pauls_sig, tx_funding_script ];
                var tx_funding_txhex_paul = tapscript.Tx.encode( tx_funding_txdata_paul ).hex;
                var post_funding_txid = tapscript.Tx.util.getTxid( tx_funding_txhex_paul );
                var post_funding_vout = 0;
                var post_funding_amt = tx_funding_amt - 500;
                var post_funding_txdata_paul = tapscript.Tx.create({
                  vin  : [{
                    txid: post_funding_txid,
                    vout: post_funding_vout,
                    prevout: {
                      value: post_funding_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( post_funding_address_paul )
                    },
                  }],
                  vout : [{
                    value: post_funding_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( refund_address )
                  }]
                });
                var post_funding_pauls_sig = tapscript.Signer.segwit.sign( privkey, post_funding_txdata_paul, 0, { script: post_funding_script_paul });
                var post_funding_txhex_paul = tapscript.Tx.encode( post_funding_txdata_paul ).hex;
                var tx_refund_txid = tapscript.Tx.util.getTxid( post_funding_txhex_paul );
                var tx_refund_vout = 0;
                var tx_refund_amt = post_funding_amt - 500;
                var tx_refund_txdata_paul = tapscript.Tx.create({
                  vin  : [{
                    txid: tx_refund_txid,
                    vout: tx_refund_vout,
                    //todo: fix the sequence
                    // sequence: 144 * 7,
                    sequence: 1 * 7,
                    prevout: {
                      value: tx_refund_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( refund_address )
                    },
                  }],
                  vout : [{
                    value: tx_refund_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( vickys_address )
                  }]
                });
                //the following sig should move the money from the refund address to vicky
                var tx_refund_pauls_sig = tapscript.Signer.taproot.sign( privkey, tx_refund_txdata_paul, 0, { extension: tapscript.Tap.encodeScript( refund_scripts[ 1 ] ) });
                tx_refund_txdata_paul.vin[ 0 ].witness = [ 0, tx_refund_pauls_sig, refund_scripts[ 1 ], refund_cblock ];
                var tx_refund_txhex = tapscript.Tx.encode( tx_refund_txdata_paul ).hex;
                //versions for vicky
                var tx_funding_txdata_vicky = tapscript.Tx.create({
                  vin  : [{
                    txid: tx_funding_txid,
                    vout: tx_funding_vout,
                    prevout: {
                      value: tx_funding_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( tx_funding_address )
                    },
                  }],
                  vout : [{
                    value: tx_funding_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( post_funding_address_vicky )
                  }]
                });
                var tx_funding_pauls_sig_vicky = tapscript.Signer.segwit.sign( privkey, tx_funding_txdata_vicky, 0, { script: tx_funding_script });
                tx_funding_txdata_vicky.vin[ 0 ].witness = [ 0, 0, tx_funding_pauls_sig_vicky, tx_funding_script ];
                var tx_funding_txhex_vicky = tapscript.Tx.encode( tx_funding_txdata_vicky ).hex;
                var post_funding_txid = tapscript.Tx.util.getTxid( tx_funding_txhex_vicky );
                var other_partys_to_reveal_txid = post_funding_txid;
                var post_funding_vout = 0;
                var post_funding_amt = tx_funding_amt - 500;
                var post_funding_txdata_vicky = tapscript.Tx.create({
                  vin  : [{
                    txid: post_funding_txid,
                    vout: post_funding_vout,
                    prevout: {
                      value: post_funding_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( post_funding_address_vicky )
                    },
                  }],
                  vout : [{
                    value: post_funding_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( refund_address )
                  }]
                });
                var post_funding_pauls_sig_vicky = tapscript.Signer.segwit.sign( privkey, post_funding_txdata_vicky, 0, { script: post_funding_script_vicky });
                var post_funding_txhex_vicky = tapscript.Tx.encode( post_funding_txdata_vicky ).hex;
                var tx_refund_txid = tapscript.Tx.util.getTxid( post_funding_txhex_vicky );
                var other_partys_to_delay_txid = tx_refund_txid;
                var tx_refund_vout = 0;
                var tx_refund_amt = post_funding_amt - 500;
                var tx_refund_txdata_vicky = tapscript.Tx.create({
                  vin  : [{
                    txid: tx_refund_txid,
                    vout: tx_refund_vout,
                    //todo: fix the sequence
                    // sequence: 144 * 7,
                    sequence: 1 * 7,
                    prevout: {
                      value: tx_refund_amt,
                      scriptPubKey: tapscript.Address.toScriptPubKey( refund_address )
                    },
                  }],
                  vout : [{
                    value: tx_refund_amt - 500,
                    scriptPubKey: tapscript.Address.toScriptPubKey( vickys_address )
                  }]
                });
                //the following sig should move the money from the refund address to vicky
                var tx_refund_pauls_sig_vicky = tapscript.Signer.taproot.sign( privkey, tx_refund_txdata_vicky, 0, { extension: tapscript.Tap.encodeScript( refund_scripts[ 1 ] ) });
                var transitioning_to = 0;
                var msgnum = 2;
                var msg_to_sign = `${channel_identifier}${transitioning_to}${msgnum}${tx_funding_pauls_sig_vicky.hex}${post_funding_pauls_sig_vicky.hex}${bytesToHex( tx_refund_pauls_sig_vicky )}`;
                var msghash = await sha256( msg_to_sign );
                var sig = await nobleSecp256k1.sign( msghash, privkey );
                var pauls_sigs = [ msgnum, channel_identifier, sig, tx_funding_pauls_sig_vicky.hex, post_funding_pauls_sig_vicky.hex, bytesToHex( tx_refund_pauls_sig_vicky ) ];
                var channel = {}
                channel[ "force_close_txs" ] = {
                    other_partys_to_reveal_txid,
                    other_partys_to_delay_txid,
                    to_reveal: tx_funding_txhex_paul,
                    to_delay: post_funding_txhex_paul,
                    final_tx: tx_refund_txhex,
                    vickys_publication_hash,
                    vickys_revocation_hash,
                    pauls_publication_preimage,
                    pauls_revocation_preimage,
                }
                channel[ "tx_funding_amt" ] = tx_funding_amt;
                channel[ "tx_funding_address" ] = tx_funding_address;
                channel[ "tx_funding_script" ] = tx_funding_script;
                channel[ "vickys_key" ] = vickys_key;
                channel[ "vickys_address" ] = vickys_address;
                channel[ "balance" ] = {
                    reserve: 0,
                    local: 0,
                    remote: tx_refund_amt - 500,
                }
                channel[ "privkey" ] = privkey;
                channel[ "pauls_key" ] = pauls_key;
                db[ channel_identifier ][ 2 ] = channel;
                var texttowrite = JSON.stringify( db );
                fs.writeFileSync( "db.txt", texttowrite, function() {return;});
                return sendResponse( response, JSON.stringify( pauls_sigs ), 200, {'Content-Type': 'application/json'} );
            }
            if ( parts.path == "/api/v1/send_pmt" || parts.path == "/api/v1/send_pmt/" ) {
                //ensure the user sent what you expect
                var is_valid_json = isValidJson( formattedData );
                if ( !is_valid_json ) return;
                var arr = JSON.parse( formattedData );
                if ( arr.length != 5 ) return;
                //item 0 should be the msgnum, which should be 7
                if ( arr[ 0 ] != 7 ) return;
                //item 1 should be the channel id
                if ( !isValidHex( arr[ 1 ] ) || arr[ 1 ].length != 32 ) return;
                if ( !Object.keys( db ).includes( arr[ 1 ] ) ) return;
                var channel_identifier = arr[ 1 ];
                //item 2 should be an ecdsa signature
                if ( !isValidHex( arr[ 2 ] ) || arr[ 2 ].length > 144 ) return;
                //item 3 should be the max fee, a number between 0.01 and 0.99, inclusive
                if ( typeof arr[ 3 ] != "number" || String( arr[ 3 ] ).length > 4 || String( arr[ 3 ] ).length < 3 ) return;
                if ( arr[ 3 ] < 0.01 || arr[ 3 ] > 0.99 ) return;
                //item 4 should be an ln invoice
                if ( !isValidInvoice( arr[ 4 ] ) ) return;
                var invoice = arr[ 4 ];
                var pauls_key = db[ channel_identifier ][ 2 ][ "pauls_key" ];
                var privkey = db[ channel_identifier ][ 2 ][ "privkey" ];
                var data_from_vicky = arr;
                var vickys_key = db[ channel_identifier ][ 2 ][ "vickys_key" ];
                if ( !( "old_states" in db[ channel_identifier ][ 2 ] ) ) db[ channel_identifier ][ 2 ][ "old_states" ] = [];
                var transitioning_to = db[ channel_identifier ][ 2 ][ "old_states" ].length;
                var msgnum = 7;
                var msg_to_sign = `${channel_identifier}${transitioning_to}${msgnum}${data_from_vicky[ 3 ]}${data_from_vicky[ 4 ]}`;
                var msghash = await sha256( msg_to_sign );
                var sig = data_from_vicky[ 2 ];
                var sig_is_valid = await nobleSecp256k1.verify( sig, msghash, vickys_key );
                if ( !sig_is_valid ) return;
                //extract the amount and pmthash from the invoice and pass them back in a request
                //but with the amount multiplied by 1.01 (or whatever the user set as a max fee)
                var decoded_invoice = bolt11.decode( invoice );
                var amt = decoded_invoice[ "satoshis" ];
                var percent = 1 + arr[ 3 ];
                var request_amt = Math.floor( percent * amt );
                if ( !request_amt ) return;
                var pmthash = getInvoicePmthash( invoice );
                if ( !isValidHex( pmthash ) || pmthash.length != 64 ) return;
                var transitioning_to = db[ channel_identifier ][ 2 ][ "old_states" ].length;
                var msgnum = 5;
                var msg_to_sign = `${channel_identifier}${transitioning_to}${msgnum}${pmthash}${request_amt}`;
                var msghash = await sha256( msg_to_sign );
                var sig = await nobleSecp256k1.sign( msghash, privkey );
                var reply = JSON.stringify( [ msgnum, channel_identifier, sig, pmthash, request_amt ] );
                //todo: put this pmthash + amt in Vicky's db entry with a timestamp
                //if, within 30 seconds, she says she wants to pay it, good. Otherwise,
                //remove it from the db and reject her request.
                return sendResponse( response, reply, 200, {'Content-Type': 'application/json'} );
            }
            if ( parts.path == "/api/v1/update_state_0" || parts.path == "/api/v1/update_state_0/" ) {
                
            }
            return sendResponse( response, `404 page not found`, 200, {'Content-Type': 'text/plain'} );
        });
    }
};

const server = http.createServer( requestListener );
server.listen( 8080 );
