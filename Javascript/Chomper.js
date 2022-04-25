#!/usr/bin/env node
//
//  CVEChomper
//      By Lepus Hare. 
//      Original: https://github.com/L3pu5/CVEChomper
//

const baseUrl = "https://cve.circl.lu/api/cve/";
var CVE, CVESTRING;

if(process.argv.length < 3){
    console.log("Usage: [node] Chomper <CVE> <flags>");
    console.log("    Flags");
    console.log('     "M": "Modified"');
    console.log('     "P": "Published"');
    console.log('     "x": "access"');
    console.log('     "a": "assigner"');
    console.log('     "c": "capec"');
    console.log('     "t": "cvss-time"');
    console.log('     "v": "cvss-vector"');
    console.log('     "C": "cwe"');
    console.log('     "i": "id"');
    console.log('     "I": "impact"');
    console.log('     "l": "last-modified"');
    console.log('     "r": "references"');
    console.log('     "m": "refmap"');
    console.log('     "u": "summary"');
    console.log('     "p": "vulnerable_product"');
    console.log('     "f": "vulnerable_configuration"');
    process.exit(1);
}


if(process.argv[2].substring(0, 3) === "CVE"){
    CVE = process.argv[2];
}else{
    CVE = "CVE-" + process.argv[2];
}
CVESTRING = CVE;

var translate = {
    "M": "Modified",
    "P": "Published", //Published
    "x": "access", //Access Object
    "a": "assigner", //Assignmer
    "c": "capec", //Capec
    "t": "cvss-time", //Time
    "v": "cvss-vector", //Vector
    "C": "cwe", //CWE identifier
    "i": "id", //ID
    "I": "impact", //Impact (CIA Triad)
    "l": "last-modified", //lastmodified
    "r": "references", //references
    "m": "refmap", //refmap
    "u": "summary", //Summary outside of Capec
    "p": "vulnerable_product", //Products
    "f": "vulnerable_configuration", //Configuration
}

var args = {
    "i": false, //ID
    "C": false, //CWE identifier
    "I": false, //Impact (CIA Triad)
    "a": false, //Assignmer
    "M": false, //Modified
    "P": false, //Published
    "t": false, //Time
    "u": false, //Summary outside of Capec
    "v": false, //Vector
    "p": false, //Products
    "f": false, //Configuration
    "x": false, //Access Object
    "c": false, //Capec
    "l": false, //lastmodified
    "r": false, //references
    "m": false, //refmap
}

var split;
if(process.argv.length == 4){
    split = process.argv[3];
}else{
    split = "CciIurpf"
}

split = split.split('');

//Read in args:
for(var char in split){
    args[split[char]] = translate[split[char]]
}


const https = require('https');
const { exit } = require('process');
https.get(baseUrl + CVE, _result => {
    var _responseData = '';
    _result.on('data', _data => {_responseData += _data;});
    _result.on('end', ()=>{CVE = JSON.parse(_responseData); Post();});
});

function Post(){
    console.log("----------------------------------------------------");
    console.log("                   " + CVESTRING);
    console.log("----------------------------------------------------");
    for(var arg in args){
        if(args[arg]){
            if(typeof CVE[args[arg]] === "object"){
                console.log(args[arg]);
                console.log("----------------------------------------------------");
                for(var iter in CVE[args[arg]]){
                    console.log(iter + ": %s", CVE[args[arg]][iter]);
                }
                console.log("----------------------------------------------------");
            }else{
                console.log(args[arg] + ":" + CVE[args[arg]]);
            }
        }
    }
}