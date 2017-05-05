"use strict";

function search() {
    var address = document.getElementById('address').value;
    var index = document.getElementById('index').value;
    $.ajax({
        method: 'POST',
        url: 'http://localhost:8545',
        data: '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"' + address + '","data":"0x27ee5376' + padTo64(toHex(index)) + '"},"latest"],"id":1}',
        success: function (data) {
            if(data.result){
                setCustomerInfo(data.result.slice(2));
            }else{
                setResult(data.error.message);
            }
        },
        error: function () {
            setReusult('Cannot reach server');
        }
    });

    function setResult(result) {
        document.getElementById('result').innerHTML = result;
    }

    function setCustomerInfo(hexInfo) {
        if(hexInfo.endsWith('1')) {
            var name = toBytes(removePaddingZero(hexInfo.substr(0, 64)));
            var phone = toBytes(removePaddingZero(hexInfo.substr(64, 64)));
            setResult('name:' + name + '<br \>phone: ' + phone);
        } else {
            setResult('This customer is not exist');
        }
    }

    function toHex(str) {
        var result = '';
        var length = str.length;
        for(var i = 0; i < length; ++i) {
            result += str.charCodeAt(i) >> 4;
            result += str.charCodeAt(i) & 0xf;
        }
        return result;
    }

    function toBytes(hex) {
        var result = '';
        var length = hex.length;
        if(length % 2) {
            result = '0' + result;
            length++;
        }

        for(var i = 0; i < length; i += 2) {
            result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        return result;
    }

    function padTo64(str) {
        var length = str.length;
        if(length >= 64) {
            return str.substr(0, 64);
        }
        while(str.length < 64) {
            str += '0';
        }
        return str;
    }

    function removePaddingZero(str) {
        var pos = str.indexOf('00');
        if(pos >= 0) {
            return str.substr(0, pos);
        } else {
            return str;
        }
    }
}